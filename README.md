![Banner](banner.png)

# file-metadata-analyzer
Extracts and analyzes file metadata (e.g., creation date, author, software used to create the file) to identify inconsistencies or anomalies that could indicate tampering or malicious origin. It runs the external `exiftool` executable and reads its JSON output. - Focused on File operations and analysis

## Requirements
- Python 3
- The `exiftool` executable installed as a system program, in the system PATH or named with `--exiftool_path`. There is no Python package that provides it, and `requirements.txt` lists no Python dependencies.

## Install
`git clone https://github.com/ShadowStrikeHQ/file-metadata-analyzer`

## Usage
`python3 main.py file_path [--json] [--output OUTPUT] [--exiftool_path EXIFTOOL_PATH]`

Example: `python3 main.py suspicious_file.pdf`

The report names the checks that ran and the metadata fields that were found on every run. If no checkable metadata fields were present, the report says no checkable metadata fields were present and no checks could run, instead of a clean result, and the run exits with status 1.

An output path that resolves to the input file itself (the same path, a `./` alias, or a symlink to it) is refused at exit 1 before any write, so a report never replaces the analyzed file.

## Parameters
- `file_path`: Path to the file to analyze (positional, required)
- `-h`: Show help message and exit
- `--json`: Output metadata in JSON format.
- `--output`, `-o`: Path to output file to write the metadata
- `--exiftool_path`: Path to the ExifTool executable. If not provided, it will be assumed to be in the system PATH.

## License
Copyright (c) ShadowStrikeHQ
