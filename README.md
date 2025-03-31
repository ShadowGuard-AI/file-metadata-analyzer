# file-metadata-analyzer
Extracts and analyzes file metadata (e.g., creation date, author, software used to create the file) to identify inconsistencies or anomalies that could indicate tampering or malicious origin. Uses libraries like `exiftool` via `pyexiftool`. - Focused on File operations and analysis

## Install
`git clone https://github.com/ShadowStrikeHQ/file-metadata-analyzer`

## Usage
`./file-metadata-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--json`: Output metadata in JSON format.
- `--output`: Path to output file to write the metadata
- `--exiftool_path`: Path to the ExifTool executable. If not provided, it will be assumed to be in the system

## License
Copyright (c) ShadowStrikeHQ
