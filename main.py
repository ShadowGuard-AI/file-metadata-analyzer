import argparse
import logging
import subprocess
import json
import os
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Extracts and analyzes file metadata to identify inconsistencies or anomalies."
    )
    parser.add_argument("file_path", help="Path to the file to analyze.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output metadata in JSON format.",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Path to output file to write the metadata",
        default=None
    )
    parser.add_argument(
        "--exiftool_path",
        help="Path to the ExifTool executable. If not provided, it will be assumed to be in the system's PATH.",
        default="exiftool"
    )

    return parser


def extract_metadata(file_path, exiftool_path="exiftool"):
    """
    Extracts metadata from a file using ExifTool.

    Args:
        file_path (str): The path to the file.
        exiftool_path (str, optional): Path to the ExifTool executable. Defaults to "exiftool".

    Returns:
        dict: A dictionary containing the extracted metadata.  Returns None if an error occurs.
    """
    try:
        # Pass the plain file path as one list argument. With shell=False the
        # path is not shell interpreted, so no quoting is needed or wanted.
        # The command is an argv list with shell=False, and -j asks exiftool for
        # JSON. For one input file the JSON is a list holding one dict, which is
        # why extract_metadata returns element zero and treats any other shape
        # as an error instead of guessing.
        command = [exiftool_path, "-j", str(file_path)]

        # Execute the command and capture the output.  Use shell=False for security.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
        stdout, stderr = process.communicate()

        # Check the return code.
        if process.returncode != 0:
            logging.error(f"ExifTool failed with error: {stderr.decode()}")
            return None

        # Parse the JSON output.
        try:
            metadata = json.loads(stdout.decode())
            if isinstance(metadata, list) and len(metadata) > 0:
                return metadata[0] # Exiftool returns a list of one dictionary when analyzing single files
            else:
                logging.error(f"Unexpected ExifTool output: {metadata}")
                return None
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode JSON: {e}")
            logging.error(f"Raw output from exiftool: {stdout.decode()}") # Print full exiftool output for debugging.
            return None

    except FileNotFoundError:
        logging.error(f"ExifTool not found at {exiftool_path}.  Please ensure it is installed and in your PATH, or provide the full path to the executable.")
        return None
    except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        return None


EXTENSION_MIME_ALIASES = {
    "jpg": {"image/jpeg"},
    "jpeg": {"image/jpeg"},
    "jpe": {"image/jpeg"},
    "txt": {"text/plain"},
    "text": {"text/plain"},
    "png": {"image/png"},
    "gif": {"image/gif"},
    "pdf": {"application/pdf"},
    "htm": {"text/html"},
    "html": {"text/html"},
    "json": {"application/json"},
    "xml": {"application/xml", "text/xml"},
    "zip": {"application/zip", "application/x-zip-compressed"},
    "csv": {"text/csv", "text/plain"},
    "mp3": {"audio/mpeg"},
    "mp4": {"video/mp4"},
    "mov": {"video/quicktime"},
    "tif": {"image/tiff"},
    "tiff": {"image/tiff"},
    "bmp": {"image/bmp", "image/x-ms-bmp"},
    "svg": {"image/svg+xml"},
    "doc": {"application/msword"},
    "docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    "xls": {"application/vnd.ms-excel"},
    "xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    "ppt": {"application/vnd.ms-powerpoint"},
    "pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    "odt": {"application/vnd.oasis.opendocument.text"},
    "rtf": {"application/rtf", "text/rtf"},
    "gz": {"application/gzip", "application/x-gzip"},
    "tar": {"application/x-tar"},
    "wav": {"audio/wav", "audio/x-wav"},
    "avi": {"video/x-msvideo"},
    "md": {"text/markdown", "text/plain"},
}

NO_CHECKABLE_LINE = "No checkable metadata fields were present and no checks could run."


def checkable_fields_present(metadata):
    if not metadata:
        return False
    if "CreatorTool" in metadata:
        return True
    if "FileModifyDate" in metadata and "FileCreateDate" in metadata:
        return True
    if "FileTypeExtension" in metadata and "MIMEType" in metadata:
        return True
    return False


def analyze_metadata(metadata):
    """
    Analyzes the extracted metadata for inconsistencies or anomalies.

    Args:
        metadata (dict): A dictionary containing the metadata.

    Returns:
        list: A list of strings describing potential issues, preceded by
        lines naming the checks that ran and the fields that were found.
    """
    issues = []

    if not metadata:
        return [NO_CHECKABLE_LINE]

    fields_found = sorted(metadata.keys())
    checks_run = []
    if "CreatorTool" in metadata:
        checks_run.append("CreatorTool check")
    if "FileModifyDate" in metadata and "FileCreateDate" in metadata:
        checks_run.append("date order check")
    if "FileTypeExtension" in metadata and "MIMEType" in metadata:
        checks_run.append("file extension and MIME type check")

    header = [
        f"Checks run: {', '.join(checks_run) if checks_run else 'none'}",
        f"Metadata fields found: {', '.join(fields_found) if fields_found else 'none'}",
    ]
    logging.info(header[0])
    logging.info(header[1])

    # Example analysis: Check for suspicious software
    if "CreatorTool" in metadata:
        creator_tool = str(metadata["CreatorTool"]).lower()
        # A plain substring test on the creating tool's name. It catches a tool
        # that announces itself and nothing subtler, and it can fire on an
        # innocent name containing those letters. I keep it because the report
        # shows the value it fired on.
        if "malware" in creator_tool or "evil" in creator_tool:
            issues.append(f"Suspicious CreatorTool: {creator_tool}")

    # Example analysis: Check for unusual dates
    if "FileModifyDate" in metadata and "FileCreateDate" in metadata:
        modify_date = metadata["FileModifyDate"]
        create_date = metadata["FileCreateDate"]

        # Basic date comparison (more sophisticated analysis could be added)
        # The dates are compared as strings, exactly as exiftool printed them.
        # Its usual format sorts correctly as text, but two values carrying
        # different timezone offsets can order wrong, because the offset is
        # compared as characters too. This is a rough check and reads like one.
        if modify_date < create_date:
            issues.append(f"File modification date ({modify_date}) is earlier than creation date ({create_date}).")

    # Example analysis: Detect if file extension mismatches the file type indicated in the metadata
    if "FileTypeExtension" in metadata and "MIMEType" in metadata:
        file_extension = str(metadata["FileTypeExtension"]).lower()
        mime_type = str(metadata["MIMEType"]).lower()

        # Extensions in the table get an exact verdict: the MIME type is either
        # in the accepted set or it is an issue. Extensions the table does not
        # cover fall back to the older substring test, where either string
        # containing the other is close enough to pass.
        accepted = EXTENSION_MIME_ALIASES.get(file_extension)
        if accepted is None or mime_type not in accepted:
            # Keep the original substring behaviour only for extensions
            # the alias table does not cover at all.
            if accepted is not None or (file_extension not in mime_type and mime_type not in file_extension):
                issues.append(f"File extension '{file_extension}' does not match MIME type '{mime_type}'. Possible file spoofing.")

    if not checks_run:
        return header + [NO_CHECKABLE_LINE]

    if not issues:
        issues.append("No anomalies detected.")

    return header + issues


def validate_file_path(file_path):
    """
    Validates that the file path exists and is a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        bool: True if the file path is valid, False otherwise.
    """
    try:
        file_path_obj = Path(file_path).resolve() # Resolve symlinks
        if not file_path_obj.exists():
            logging.error(f"File not found: {file_path}")
            return False
        if not file_path_obj.is_file():
            logging.error(f"Not a file: {file_path}")
            return False
        return True
    except Exception as e:
        logging.error(f"Invalid file path: {file_path} - {e}")
        return False


def main():
    """
    Main function to execute the file metadata analysis.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Refuse an output path that resolves to the input file itself.
    if args.output:
        try:
            if Path(args.output).resolve() == Path(args.file_path).resolve():
                logging.error("Output path resolves to the input file. Refusing to overwrite the analyzed file.")
                print("Output path is the input file. Refusing to write the report over the analyzed file.")
                exit(1)
        except Exception as e:
            logging.error(f"Invalid output path: {args.output} - {e}")
            exit(1)

    # Input validation
    if not validate_file_path(args.file_path):
        exit(1) # Exit with error code

    # Extract metadata
    metadata = extract_metadata(args.file_path, args.exiftool_path)
    if metadata is None:
        print("Failed to extract metadata. See logs for details.")
        exit(1)


    # Analyze metadata
    issues = analyze_metadata(metadata)

    # Output results
    if args.json:
        output_str = json.dumps(metadata, indent=4)
    else:
        output_str = "\n".join(issues)

    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(output_str)
            print(f"Output written to {args.output}")
        except Exception as e:
            logging.error(f"Failed to write to output file: {e}")
            print("Error writing output to file. See logs for details.")
            exit(1)
    else:
        print(output_str)

    # This gate runs after the output has been printed or written. A file
    # whose metadata holds none of the checkable fields still produces its
    # report, and only then exits 1, so a caller gets both the evidence and
    # the failure signal.
    if not args.json and not checkable_fields_present(metadata):
        exit(1)
    if args.json and not checkable_fields_present(metadata):
        logging.error(NO_CHECKABLE_LINE)
        print(NO_CHECKABLE_LINE)
        exit(1)

if __name__ == "__main__":
    main()

# Usage Examples:
#
# 1. Analyze a file and print the analysis results to the console:
#    python main.py suspicious_file.pdf
#
# 2. Analyze a file and output the full metadata in JSON format:
#    python main.py suspicious_file.pdf --json
#
# 3. Analyze a file and save the analysis results to a file:
#    python main.py suspicious_file.pdf --output analysis_report.txt
#
# 4. Analyze a file using a specific path to ExifTool:
#    python main.py suspicious_file.pdf --exiftool_path /opt/exiftool/exiftool
#
# Offensive Tools:
# This tool itself is primarily defensive. However, it can be used in offensive scenarios:
#
# 1. Reconnaissance: Extract metadata to gather information about targets (software versions, author names, locations, etc.)
# 2. Identifying Weaknesses: Look for misconfigured software or metadata fields that could be exploited. (e.g. if CreatorTool is set to an extremely old version that is vulnerable)
# 3. Payload Delivery: While this tool doesn't directly deliver payloads, you could use the extracted metadata to craft social engineering attacks or identify file types that are more likely to be trusted by the target.
# 4. Evading Detection:  Analyze the metadata of your crafted payloads and compare them against "normal" files in the target environment to ensure the metadata doesn't raise red flags.