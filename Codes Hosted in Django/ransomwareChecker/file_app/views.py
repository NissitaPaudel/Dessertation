from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile

import olefile
import pyzipper
import yara
from django.conf import settings
from django.shortcuts import redirect, render


# ---------------------------------------------------------
# YARAShield processing limits
# ---------------------------------------------------------

# Maximum uploaded file size: 15 MB.
MAX_UPLOAD_SIZE = 15 * 1024 * 1024

# Maximum number of files inside a ZIP/OOXML package.
MAX_ARCHIVE_MEMBERS = 200

# Maximum combined expanded size of an archive: 30 MB.
MAX_ARCHIVE_UNCOMPRESSED_SIZE = 30 * 1024 * 1024

# Maximum number of streams inspected inside an OLE object.
MAX_OLE_STREAMS = 200

# Maximum combined size of OLE streams: 30 MB.
MAX_OLE_UNCOMPRESSED_SIZE = 30 * 1024 * 1024

# Maximum size of one internal file/stream: 15 MB.
MAX_INTERNAL_FILE_SIZE = 15 * 1024 * 1024

# Maximum number of approved archive passwords.
MAX_PASSWORD_CANDIDATES = 20

# Used for POST → Redirect → GET.
SCAN_RESULT_SESSION_KEY = "yarashield_scan_result"


# ---------------------------------------------------------
# Load approved archive passwords
# ---------------------------------------------------------

def load_archive_passwords():
    """
    Load approved archive passwords from settings.py.

    These passwords are used only when an encrypted ZIP member
    is encountered. The application does not perform unrestricted
    password guessing or password cracking.
    """

    approved_passwords = []

    configured_passwords = getattr(
        settings,
        "ARCHIVE_PASSWORD_CANDIDATES",
        [],
    )

    if not isinstance(
        configured_passwords,
        (list, tuple, set),
    ):
        print(
            "ARCHIVE_PASSWORD_CANDIDATES must be "
            "a list, tuple or set."
        )
        return approved_passwords

    for configured_password in configured_passwords:

        if isinstance(configured_password, bytes):
            password_bytes = configured_password.strip()

        else:
            password_text = str(
                configured_password
            ).strip()

            if not password_text:
                continue

            password_bytes = password_text.encode(
                "utf-8"
            )

        if not password_bytes:
            continue

        if password_bytes not in approved_passwords:
            approved_passwords.append(
                password_bytes
            )

        if (
            len(approved_passwords)
            >= MAX_PASSWORD_CANDIDATES
        ):
            break

    return approved_passwords


# ---------------------------------------------------------
# Main content scanning function
# ---------------------------------------------------------

def scan_uploaded_content(
    rules,
    file_data,
    file_name,
    archive_passwords=None,
):
    """
    Scan uploaded content entirely in memory.

    The function examines:
    - the original uploaded file;
    - ordinary ZIP archive members;
    - password-protected ZIP members;
    - ZIP-based Office documents such as DOCX;
    - embedded OLE objects and streams;
    - combined expanded archive content.

    Nothing is executed and no temporary filesystem copy
    is intentionally created by this view.
    """

    password_candidates = archive_passwords or []

    scan_hits = []
    recorded_hits = set()

    # -----------------------------------------------------
    # Scan one byte sequence with YARA
    # -----------------------------------------------------

    def scan_target(target_data, source_name):

        if not target_data:
            return

        matches = rules.match(
            data=target_data,
            timeout=30,
            externals={
                "uploaded_filename": source_name,
            },
        )

        # YARA returns all matching rules.
        for match in matches:

            hit_key = (
                match.rule,
                source_name,
            )

            if hit_key in recorded_hits:
                continue

            recorded_hits.add(hit_key)

            scan_hits.append(
                {
                    "match": match,
                    "source": source_name,
                }
            )

    # -----------------------------------------------------
    # Inspect an OLE compound object
    # -----------------------------------------------------

    def scan_ole_container(
        container_data,
        container_name,
    ):

        if not container_data:
            return

        try:
            is_ole_file = olefile.isOleFile(
                data=container_data
            )

        except (
            OSError,
            IOError,
            ValueError,
            TypeError,
        ):
            return

        if not is_ole_file:
            return

        try:
            with olefile.OleFileIO(
                BytesIO(container_data)
            ) as ole:

                stream_paths = ole.listdir(
                    streams=True,
                    storages=False,
                )

                if len(stream_paths) > MAX_OLE_STREAMS:
                    raise ValueError(
                        "The embedded OLE object contains "
                        "more than 200 streams and cannot "
                        "be inspected safely."
                    )

                total_stream_size = 0

                combined_ole_data = bytearray(
                    container_data
                )

                for stream_path in stream_paths:

                    stream_name = "/".join(
                        stream_path
                    )

                    try:
                        stream_size = ole.get_size(
                            stream_path
                        )

                    except (
                        OSError,
                        IOError,
                    ):
                        print(
                            "Could not determine OLE "
                            f"stream size: {stream_name}"
                        )
                        continue

                    total_stream_size += stream_size

                    if (
                        total_stream_size
                        > MAX_OLE_UNCOMPRESSED_SIZE
                    ):
                        raise ValueError(
                            "The embedded OLE content "
                            "expands beyond the permitted "
                            "30 MB inspection limit."
                        )

                    if (
                        stream_size
                        > MAX_INTERNAL_FILE_SIZE
                    ):
                        print(
                            "Skipped oversized OLE stream: "
                            f"{stream_name}"
                        )
                        continue

                    try:
                        stream_data = ole.openstream(
                            stream_path
                        ).read()

                    except (
                        OSError,
                        IOError,
                    ) as error:

                        print(
                            "Could not inspect OLE stream "
                            f"{stream_name}: {error}"
                        )

                        continue

                    source_name = (
                        f"{container_name}"
                        f"!OLE!{stream_name}"
                    )

                    # Scan each OLE stream individually.
                    scan_target(
                        stream_data,
                        source_name,
                    )

                    # Also add it to combined OLE content.
                    combined_ole_data.extend(b"\n")

                    combined_ole_data.extend(
                        stream_name.encode(
                            "utf-8",
                            errors="ignore",
                        )
                    )

                    combined_ole_data.extend(b"\n")

                    combined_ole_data.extend(
                        stream_data
                    )

                # Scan all OLE content together.
                scan_target(
                    bytes(combined_ole_data),
                    f"{container_name}!expanded-OLE",
                )

        except ValueError:
            raise

        except (
            OSError,
            IOError,
        ) as error:

            print(
                "Could not parse OLE container "
                f"{container_name}: {error}"
            )

    # -----------------------------------------------------
    # Read one archive member
    # -----------------------------------------------------

    def read_archive_member(
        archive,
        member,
    ):

        member_is_encrypted = bool(
            member.flag_bits & 0x1
        )

        # Normal unencrypted member.
        if not member_is_encrypted:

            try:
                return archive.read(member)

            except (
                RuntimeError,
                ValueError,
                NotImplementedError,
                BadZipFile,
                OSError,
            ) as error:

                print(
                    "Could not inspect archive member "
                    f"{member.filename}: {error}"
                )

                return None

        # Encrypted member.
        print(
            "Encrypted archive member detected: "
            f"{member.filename}"
        )

        if not password_candidates:

            raise ValueError(
                "The archive is password-protected, "
                "but no approved archive passwords "
                "are configured."
            )

        # Try only the approved passwords.
        for password in password_candidates:

            try:
                member_data = archive.read(
                    member,
                    pwd=password,
                )

                print(
                    "Encrypted archive member "
                    "successfully opened using an "
                    "approved research password: "
                    f"{member.filename}"
                )

                return member_data

            except (
                RuntimeError,
                ValueError,
                NotImplementedError,
                BadZipFile,
                OSError,
            ):
                continue

        # Important:
        # unreadable encrypted content is NOT considered clean.
        raise ValueError(
            "The password-protected archive could "
            "not be inspected because none of the "
            "approved passwords could open it."
        )

    # -----------------------------------------------------
    # Stage 1 — Scan original uploaded bytes
    # -----------------------------------------------------

    scan_target(
        file_data,
        file_name,
    )

    # The original file might itself be an OLE document.
    scan_ole_container(
        file_data,
        file_name,
    )

    # -----------------------------------------------------
    # Stage 2 — Determine whether it is ZIP-based
    # -----------------------------------------------------

    # ZIP, DOCX, DOCM, XLSX and PPTX commonly start with PK.
    if not file_data.startswith(b"PK"):
        return scan_hits

    # -----------------------------------------------------
    # Stage 3 — Inspect ZIP / Office package
    # -----------------------------------------------------

    try:
        with pyzipper.AESZipFile(
            BytesIO(file_data),
            mode="r",
        ) as archive:

            members = [
                member
                for member in archive.infolist()
                if not member.is_dir()
            ]

            # Limit 1: maximum members.
            if len(members) > MAX_ARCHIVE_MEMBERS:

                raise ValueError(
                    "The archive contains more than "
                    "200 internal files and cannot "
                    "be inspected safely."
                )

            total_uncompressed_size = sum(
                member.file_size
                for member in members
            )

            # Limit 2: maximum expanded archive size.
            if (
                total_uncompressed_size
                > MAX_ARCHIVE_UNCOMPRESSED_SIZE
            ):

                raise ValueError(
                    "The archive expands beyond the "
                    "permitted 30 MB inspection limit."
                )

            combined_package_data = bytearray(
                file_data
            )

            for member in members:

                # Limit 3: maximum individual member size.
                if (
                    member.file_size
                    > MAX_INTERNAL_FILE_SIZE
                ):

                    print(
                        "Skipped oversized archive member: "
                        f"{member.filename}"
                    )

                    continue

                # Decompress/decrypt in memory.
                member_data = read_archive_member(
                    archive,
                    member,
                )

                if member_data is None:
                    continue

                source_name = (
                    f"{file_name}!{member.filename}"
                )

                # Scan the archive member separately.
                scan_target(
                    member_data,
                    source_name,
                )

                # If the internal member is an OLE object,
                # inspect its streams.
                scan_ole_container(
                    member_data,
                    source_name,
                )

                # Add accessible content to a combined scan.
                combined_package_data.extend(b"\n")

                combined_package_data.extend(
                    member.filename.encode(
                        "utf-8",
                        errors="ignore",
                    )
                )

                combined_package_data.extend(b"\n")

                combined_package_data.extend(
                    member_data
                )

            # Combined archive scan.
            scan_target(
                bytes(combined_package_data),
                f"{file_name}!expanded-package",
            )

    except ValueError:
        raise

    except BadZipFile as error:

        raise ValueError(
            "The uploaded file could not be "
            "inspected as a valid ZIP archive."
        ) from error

    except (
        RuntimeError,
        NotImplementedError,
        OSError,
    ) as error:

        raise ValueError(
            "The uploaded archive could not "
            f"be inspected: {error}"
        ) from error

    return scan_hits


# ---------------------------------------------------------
# Django view
# ---------------------------------------------------------

def Solution(request):
    """
    YARAShield file-scanning view.

    POST:
        Validate and scan one uploaded file.

    GET:
        Display the result once.

    POST → Redirect → GET means refreshing the result page
    does not automatically repeat the previous scan.
    """

    # -----------------------------------------------------
    # GET — display stored result once
    # -----------------------------------------------------

    if request.method == "GET":

        context = request.session.pop(
            SCAN_RESULT_SESSION_KEY,
            {},
        )

        return render(
            request,
            "Solution.html",
            context,
        )

    # -----------------------------------------------------
    # Default result values
    # -----------------------------------------------------

    context = {
        "file_path": None,
        "file_name": None,
        "file_size": None,
        "file_size1": None,
        "mod_time": None,
        "creat_time": None,
        "access_time": None,
        "ransomware_alert": None,
        "file_deleted": False,
        "permission_error": None,
        "name": None,
        "matched_results": [],
    }

    # -----------------------------------------------------
    # Validation stage
    # -----------------------------------------------------

    uploaded_file = request.FILES.get("file")

    if uploaded_file is None:

        context["permission_error"] = (
            "No file was selected. Please choose "
            "a file before scanning."
        )

    elif uploaded_file.size == 0:

        context["permission_error"] = (
            "The selected file is empty and "
            "cannot be scanned."
        )

    elif uploaded_file.size > MAX_UPLOAD_SIZE:

        context["permission_error"] = (
            "The selected file is larger than "
            "the permitted 15 MB upload limit."
        )

        print(
            "Upload rejected because the file "
            "exceeds 15 MB."
        )

    # -----------------------------------------------------
    # Valid upload
    # -----------------------------------------------------

    else:

        file_name = uploaded_file.name
        file_size_bytes = uploaded_file.size

        file_size_mb = round(
            file_size_bytes / (1024 * 1024),
            2,
        )

        context["file_name"] = file_name
        context["file_size1"] = file_size_bytes
        context["file_size"] = file_size_mb

        print("----------------------------------------")
        print(f"Original filename: {file_name}")
        print(f"File size: {file_size_bytes} bytes")

        file_data = None

        try:
            # -------------------------------------------------
            # Read uploaded file into memory
            # -------------------------------------------------

            uploaded_file.seek(0)

            file_data = uploaded_file.read()

            if not file_data:

                raise ValueError(
                    "The uploaded file could not "
                    "be read."
                )

            print(
                "Uploaded file successfully loaded "
                "into memory."
            )

            # -------------------------------------------------
            # Locate YARA rules
            # -------------------------------------------------

            rules_path = (
                Path(settings.BASE_DIR)
                / "file_app"
                / "rules"
                / "rules.yar"
            )

            if not rules_path.is_file():

                raise FileNotFoundError(
                    "YARA rules file was not found at: "
                    f"{rules_path}"
                )

            # -------------------------------------------------
            # Compile rules
            # -------------------------------------------------
            #
            # Current implementation compiles the ruleset
            # for each scan request.
            # -------------------------------------------------

            rules = yara.compile(
                filepath=str(rules_path),
                externals={
                    "uploaded_filename": "",
                },
            )

            print(
                f"Using YARA rules: {rules_path}"
            )

            # -------------------------------------------------
            # Automatic archive password list
            # -------------------------------------------------

            archive_passwords = (
                load_archive_passwords()
            )

            print(
                "Approved archive passwords loaded: "
                f"{len(archive_passwords)}"
            )

            # -------------------------------------------------
            # Scan content
            # -------------------------------------------------

            scan_hits = scan_uploaded_content(
                rules,
                file_data,
                file_name,
                archive_passwords=archive_passwords,
            )

            # -------------------------------------------------
            # Collect ALL matching rules
            # -------------------------------------------------

            matched_results = []
            seen_rules = set()

            for hit in scan_hits:

                match = hit["match"]
                match_source = hit["source"]

                # A rule may match several internal streams.
                # Display each rule once in the interface.
                if match.rule in seen_rules:
                    continue

                seen_rules.add(match.rule)

                metadata = match.meta or {}

                matched_result = {
                    "rule": match.rule,

                    "family": metadata.get(
                        "family",
                        metadata.get(
                            "category",
                            "Not specified",
                        ),
                    ),

                    "description": metadata.get(
                        "description",
                        "No description provided",
                    ),

                    "indicator_type": metadata.get(
                        "indicator_type",
                        "Not specified",
                    ),

                    "confidence": metadata.get(
                        "confidence",
                        "Not specified",
                    ),

                    "source": match_source,
                }

                matched_results.append(
                    matched_result
                )

                print(
                    f"Matched YARA rule: {match.rule}"
                )

                print(
                    f"Matched source: {match_source}"
                )

                print(
                    "Detected family/category: "
                    f"{matched_result['family']}"
                )

                print(
                    "Description: "
                    f"{matched_result['description']}"
                )

                print(
                    "Indicator type: "
                    f"{matched_result['indicator_type']}"
                )

                # -------------------------------------------------
                # Detailed matched patterns stays in terminal
                # -------------------------------------------------

                for string_match in match.strings:

                    identifier = getattr(
                        string_match,
                        "identifier",
                        None,
                    )

                    if identifier is not None:

                        print(
                            "Matched pattern: "
                            f"{identifier}"
                        )

                        instances = getattr(
                            string_match,
                            "instances",
                            [],
                        )

                        for instance in instances:

                            offset = getattr(
                                instance,
                                "offset",
                                "unknown",
                            )

                            print(
                                "  Pattern offset: "
                                f"{offset}"
                            )

                    elif (
                        isinstance(
                            string_match,
                            tuple,
                        )
                        and len(string_match) >= 2
                    ):

                        print(
                            "Matched pattern: "
                            f"{string_match[1]}"
                        )

            # -------------------------------------------------
            # To Prepare webpage result
            # -------------------------------------------------

            context["matched_results"] = (
                matched_results
            )

            context["ransomware_alert"] = bool(
                matched_results
            )

            if matched_results:

                context["name"] = ", ".join(
                    result["rule"]
                    for result in matched_results
                )

            else:

                context["name"] = None

            # Kept for compatibility with current template.
            # No permanent application copy was created.
            context["file_deleted"] = True

            print(
                "YARA scan completed: "
                f"{len(matched_results)} unique "
                "rule match(es)."
            )

        # -----------------------------------------------------
        # for error handling
        # -----------------------------------------------------

        except yara.TimeoutError:

            context["ransomware_alert"] = None

            context["permission_error"] = (
                "The YARA scan exceeded the permitted "
                "time and was stopped. No detection "
                "conclusion can be made."
            )

            print(
                context["permission_error"]
            )

        except yara.SyntaxError as error:

            context["ransomware_alert"] = None

            context["permission_error"] = (
                "The installed YARA rules contain "
                f"a syntax error: {error}"
            )

            print(
                context["permission_error"]
            )

        except yara.Error as error:

            context["ransomware_alert"] = None

            context["permission_error"] = (
                "YARA could not complete the scan. "
                "No detection conclusion can be made. "
                f"Technical information: {error}"
            )

            print(
                context["permission_error"]
            )

        except FileNotFoundError as error:

            context["ransomware_alert"] = None

            context["permission_error"] = str(
                error
            )

            print(
                context["permission_error"]
            )

        except PermissionError:

            context["ransomware_alert"] = None

            context["permission_error"] = (
                "Permission was denied while reading "
                "the uploaded file."
            )

            print(
                context["permission_error"]
            )

        except MemoryError:

            context["ransomware_alert"] = None

            context["permission_error"] = (
                "The file could not be scanned because "
                "there was not enough available memory."
            )

            print(
                context["permission_error"]
            )

        except ValueError as error:

            context["ransomware_alert"] = None

            context["permission_error"] = str(
                error
            )

            print(
                "Inspection error: "
                f"{error}"
            )

        except OSError as error:

            context["ransomware_alert"] = None

            context["permission_error"] = (
                "A file-processing error occurred. "
                "No clean verdict was issued."
            )

            print(
                "File-processing error: "
                f"{error}"
            )

        except Exception as error:

            context["ransomware_alert"] = None

            context["permission_error"] = (
                "An unexpected scanning error occurred. "
                "No detection conclusion can be made."
            )

            print(
                "Unexpected scanning error: "
                f"{type(error).__name__}: {error}"
            )

        finally:
            # -------------------------------------------------
            # to release uploaded data
            # -------------------------------------------------

            file_data = None

            try:
                uploaded_file.close()

            except Exception as close_error:

                print(
                    "Uploaded stream could not be "
                    "closed normally: "
                    f"{close_error}"
                )

            print(
                "In-memory uploaded data released."
            )

    # ---------------------------------------------------------
    # POST → Redirect → GET
    # ---------------------------------------------------------

    request.session[
        SCAN_RESULT_SESSION_KEY
    ] = context

    return redirect(
        f"{request.path}#scanning"
    )


# Supports URL configurations using lowercase "solution".
solution = Solution


# ---------------------------------------------------------
# Other pages
# ---------------------------------------------------------

def home(request):
    return render(
        request,
        "Home.html",
    )


def about(request):
    return render(
        request,
        "About.html",
    )


def programs(request):
    return render(
        request,
        "Program.html",
    )