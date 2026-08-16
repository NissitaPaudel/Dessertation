import "hash"

/*
    YARAShield locked research ruleset
    Version: 1.0
    Date: 2026-08-03
*/

rule RANSOM_WannaCry_YARAShield
{
    meta:
        description = "Detects multiple static indicators associated with WannaCry ransomware"
        author = "Nischita Paudel"
        date = "2026-08-03"
        family = "WannaCry"
        aliases = "WannaCrypt, WanaCrypt0r, WCry"
        indicator_type = "Static strings and PE file header"
        purpose = "Controlled MSc research evaluation"
        source = "Indicators derived from Microsoft and CISA reporting"
        
    strings:
        $wc_service = "mssecsvc2.0" ascii wide nocase
        $wc_scheduler = "tasksche.exe" ascii wide nocase
        $wc_decryptor = "@WanaDecryptor@.exe" ascii wide nocase
        $wc_note = "@Please_Read_Me@.txt" ascii wide nocase
        $wc_password = "WNcry@2ol7" ascii wide
        $wc_registry = "WanaCrypt0r" ascii wide nocase
        $wc_extension = ".WNCRY" ascii wide nocase
        $wc_killswitch = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii wide nocase

    condition:
        filesize > 2 and
        uint16(0) == 0x5A4D and
        3 of ($wc_*)
}
rule RANSOM_Locky_YARAShield
{
    meta:
        description = "Detects the verified Locky ransomware evaluation sample"
        author = "Nischita Paudel"
        date = "2026-08-05"
        family = "Locky"
        indicator_type = "SHA-256 known-sample hash"
        purpose = "Controlled MSc research evaluation"
        confidence = "High - exact hash match"

    condition:
        filesize > 0 and
        hash.sha256(0, filesize) ==
        "f2c9ae3735430b930a81148c0bb470fcb733e456a2a942f859a1b59c4a7b2150"
}
rule RANSOM_Ryuk_YARAShield
{
    meta:
        description = "Detects static indicators associated with Ryuk ransomware"
        author = "Nischita Paudel"
        date = "2026-08-03"
        family = "Ryuk"
        indicator_type = "Ransom-note names and internal Ryuk indicators"
        purpose = "Controlled MSc research evaluation"
        source = "Rule created for YARAShield using published Ryuk indicators"
        reference_1 = "https://digital.nhs.uk/cyber-alerts/2018/cc-2627"
        reference_2 = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom%3AWin32%2FRyuk"
        reference_3 = "https://www.fortinet.com/blog/threat-research/ryuk-revisited-analysis-of-recent-ryuk-attack"

    strings:
        // Ryuk ransom-note names
        $note_1 = "RyukReadMe.html" ascii wide nocase
        $note_2 = "RyukReadMe.txt" ascii wide nocase

       // Byte patterns associated with Ryuk executables
        $code_1 = { 48 2B C3 33 DB 66 89 1C 46 48 83 FF FF 0F }
        $code_2 = { 48 8B CF E8 AB 25 00 00 85 C0 74 35 }

        // Internal indicators reported in Ryuk analysis
        $internal_1 = "FA_Scheduler" ascii wide nocase
        $internal_2 = "ocautoupds" ascii wide nocase
        $internal_3 = "CNTAoSMgr" ascii wide nocase
        $internal_4 = "hrmlog" ascii wide nocase
        $internal_5 = "UNIQUE_ID_DO_NOT_REMOVE" ascii wide
        $internal_6 = "lsaas.exe" ascii wide nocase

        // Additional indicators published by NHS Digital/NCSC
        $artefact_1 = ".RYK" ascii wide nocase
        $artefact_2 = "\\users\\Public\\finish" ascii wide nocase
        $artefact_3 = "\\users\\Public\\sys" ascii wide nocase

    condition:
        filesize > 2 and
        uint16(0) == 0x5A4D and
        (
            any of ($note_*) or
            any of ($code_*)or           
            3 of ($internal_*) or
            2 of ($artefact_*)
        )
}
rule MALDOC_RTF_MalVer_Objects_YARAShield
{
    meta:
        description = "Detects embedded RTF content with an abnormal version header and suspicious object indicators"
        original_author = "ditekSHen"
        implementation = "Integrated into YARAShield by Nischita Paudel"
        date = "2026-08-07"
        family = "Malicious Office Document"
        category = "Embedded RTF exploit document"
        indicator_type = "Abnormal RTF header and embedded object indicators"
        purpose = "Controlled MSc research evaluation"
        confidence = "Medium - suspicious document structure"
        reference = "CVE-2017-11882-associated exploit documents"

    strings:
        $obj1 = "\\objhtml" ascii
        $obj2 = "\\objdata" ascii
        $obj3 = "\\objupdate" ascii
        $obj4 = "\\objemb" ascii
        $obj5 = "\\objautlink" ascii
        $obj6 = "\\objlink" ascii

    condition:
        filesize > 100 and
        filesize <= 15728640 and

        // RTF header: {\rt
        uint32(0) == 0x74725c7b and

        // Abnormal RTF version instead of the usual {\rtf1\
        (
            uint8(4) != 0x66 or
            uint8(5) != 0x31 or
            uint8(6) != 0x5c
        ) and

        1 of ($obj*)
}