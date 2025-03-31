import argparse
import logging
import subprocess
import json
import os
from pathlib import Path
import shlex

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
        # Construct the ExifTool command.  Use shlex.quote to safely escape the file path
        # to prevent command injection.
        command = [exiftool_path, "-j", shlex.quote(str(file_path))]

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


def analyze_metadata(metadata):
    """
    Analyzes the extracted metadata for inconsistencies or anomalies.

    Args:
        metadata (dict): A dictionary containing the metadata.

    Returns:
        list: A list of strings describing potential issues.
    """
    issues = []

    if not metadata:
        return ["No metadata found or error extracting metadata."]

    # Example analysis: Check for suspicious software
    if "CreatorTool" in metadata:
        creator_tool = metadata["CreatorTool"].lower()
        if "malware" in creator_tool or "evil" in creator_tool:
            issues.append(f"Suspicious CreatorTool: {creator_tool}")

    # Example analysis: Check for unusual dates
    if "FileModifyDate" in metadata and "FileCreateDate" in metadata:
        modify_date = metadata["FileModifyDate"]
        create_date = metadata["FileCreateDate"]

        # Basic date comparison (more sophisticated analysis could be added)
        if modify_date < create_date:
            issues.append(f"File modification date ({modify_date}) is earlier than creation date ({create_date}).")

    # Example analysis: Detect if file extension mismatches the file type indicated in the metadata
    if "FileTypeExtension" in metadata and "MIMEType" in metadata:
        file_extension = metadata["FileTypeExtension"].lower()
        mime_type = metadata["MIMEType"].lower()

        if file_extension not in mime_type and mime_type not in file_extension:
            issues.append(f"File extension '{file_extension}' does not match MIME type '{mime_type}'. Possible file spoofing.")

    if not issues:
        issues.append("No anomalies detected.")

    return issues


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