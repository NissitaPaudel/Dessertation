
YARAShield

YARAShield is a Django-based web application that uses YARA rules to check uploaded files for ransomware indicators before the files are opened. It performs static analysis only: the uploaded file is never executed, and the user's original file is not changed or deleted.

This repository contains the source code submitted for an MSc Cyber Security dissertation in 2026.

Main features
Accepts one file at a time through a web browser.
Applies a 15 MB upload limit and checks that a valid file was selected.
Uses a fixed YARA ruleset containing hash, string and structure-based rules.
Checks file contents rather than relying only on the filename extension.
Inspects supported ZIP and Office containers, including embedded content.
Displays the matched rule name, identified malware type, description and indicator type.
Keeps detailed matched strings in the analysis terminal rather than displaying them in the browser.
Reports oversized, empty, unsupported or unreadable files as errors instead of describing them as safe.
How YARAShield works
A user selects and uploads a file through the Django interface.
Django validates the upload and reads the file for analysis.
Supported archives and Office containers are inspected within the configured limits.
The file contents are checked against the fixed YARA ruleset.
YARA returns any matching rules to Django.
The result and available rule information are displayed on the webpage.
A non-match is reported only as no recognised rule being found; it does not guarantee that the file is safe.
Technologies
Python 3.13
Django 6.0.7
yara-python 4.5.4
HTML and CSS
pyzipper and olefile for supported archive and document inspection
Project structure
ransomwareChecker/
├── manage.py
├── ransomwareChecker/       # Django project settings and main URLs
├── file_app/                 # Upload, validation and scanning logic
│   └── rules/
│       └── rules.yar         # Fixed YARAShield ruleset
├── templates/                # Django HTML templates
├── static/                   # CSS and other static files
└── requirements.txt          # Python dependencies, if included
Local installation

Clone the repository and move into its folder:

git clone <repository-url>
cd <repository-folder>

Create and activate a virtual environment:

py -3.13 -m venv venv
.\venv\Scripts\Activate.ps1

Install the dependencies:

python -m pip install -r requirements.txt

If a requirements file is not included, install the main packages directly:

python -m pip install Django==6.0.7 yara-python==4.5.4 pyzipper olefile

Apply the Django migrations and start the local server:

python manage.py migrate
python manage.py runserver

Open http://127.0.0.1:8000/ in a browser.

Ruleset

The fixed research ruleset covers selected indicators associated with WannaCry, Ryuk, Locky, Cerber and a malicious document class. The rule metadata records the target, indicator type, purpose and source. The rules use three methods:

Hash rules identify an exact known file.
String rules look for selected text or byte indicators and defined thresholds.
Structural rules examine suspicious features within a supported file format.

Rule matches must be interpreted carefully. A match does not always prove that a file contains ransomware, and a non-match does not prove that it is safe.

Evaluation summary

YARAShield was tested with labelled ransomware samples, a malicious document and two harmless files. One harmless file was a normal JPG. The other was a constructed 52-byte file created to examine the Ryuk rule condition. The evaluation compared the behaviour of hash, pattern and structure-based rules and documented both detections and missed samples. The small harmless test set was not sufficient to calculate a false-positive rate.

Limitations
Scans one file at a time with a maximum size of 15 MB.
Does not scan URLs, folders, network traffic, active processes or submitted hashes.
Does not provide continuous or real-time protection.
Archive and embedded-content inspection is limited by configured safety controls.
Detection is limited to indicators covered by the installed ruleset.
Does not replace antivirus software, endpoint monitoring or sandbox analysis.
No user study was conducted, so usability for non-technical users has not been proven.
Safe and ethical use

This project is intended for authorised academic and defensive security research. Do not execute live malware, test files on systems without permission, or expose malicious samples to external networks. Malicious test files are deliberately excluded from this repository.

Security before publication

The public repository must not contain:

live malware samples or password-protected malware archives;
Django secret keys, passwords, tokens or other credentials;
the local virtual environment, database, uploaded files or terminal logs;
production settings with DEBUG=True.

Use environment variables for secrets and review the .gitignore file before publishing.

Academic project information
Project: YARAShield
Author: Nischita Paudel
Programme: MSc Cyber Security
Year: 2026
Submission version: 1.0
Submission date: 17 August 2026
Licence and rule attribution

The source and purpose of each YARA rule are recorded in its metadata and in the dissertation appendix. Unless a separate LICENSE file is provided, the project remains available for academic review but no additional permission to reuse or redistribute the code is granted.
