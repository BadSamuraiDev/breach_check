import os
import yaml
import json
import argparse
import ipaddress
import logging

"""
breach_check.py

A script to check breached IPs against organizational CIDR ranges and IP lists. It processes input files
recursively or specific files as defined by command-line arguments, sanitizes IPs, and outputs matched
results to a JSON file.

Author: B'ad Samurai
GitHub: https://github.com/BadSamuraiDev/breach_check
Fedi: https://infosec.exchange/@badsamurai/

Usage:
    python breach_check.py [--breach_files FILE ...] [--cidr_files FILE ...] [--ip_files FILE ...] [--debug]

Arguments:
    --breach_files       Specify one or more breach list files to process (optional).
    --cidr_files         Specify one or more CIDR list files to process (optional).
    --ip_files           Specify one or more IP list files to process (optional).
    --debug              Enable debug-level logging for detailed output.

Features:
    - Recursively processes input files from predefined directories.
    - Sanitizes and validates IP addresses (trims whitespace, removes ports).
    - Matches IPs against CIDR ranges and IP lists.
    - Outputs results to a JSON file in the specified output directory.

Dependencies:
    - Python 3.6+
    - `pyyaml` (for YAML configuration parsing)
    - `ipaddress` (built-in, for IP address validation)

File Structure:
    - config.yaml: Defines default directories and behavior for the script.
    - breach_lists/: Contains breach IP list files.
    - org_cidr_lists/: Contains organization CIDR list files.
    - org_ip_lists/: Contains organization IP list files.
    - output/: Stores the results JSON file (ignored by Git using .gitignore).
    - requirements.txt: Lists required Python libraries for installation.

Setup:
    1. Clone the repository:
        git clone https://github.com/BadSamuraiDev/breach_check.git
    2. Navigate to the project directory:
        cd your-repository
    3. Install dependencies:
        pip install -r requirements.txt
    4. Edit `config.yaml` to customize input/output directories and behavior.

Examples:
    1. Process all files in the default directories:
        python breach_check.py
    2. Specify exact files to process:
        python breach_check.py --breach_files breach1.txt --cidr_files cidr1.txt --ip_files ip1.txt
    3. Enable debug logging:
        python breach_check.py --debug

Output:
    - A JSON file (e.g., `breach_results.json`) in the output directory containing:
        {
            "in_cidr": ["Matched IPs in CIDR ranges"],
            "in_ip_list": ["Matched IPs in the org IP list"]
        }

License:
    [Your chosen license, e.g., MIT]

Contact:
    For questions, feedback, or contributions, contact me via:
    GitHub: [https://github.com/yourusername/your-repository]
    Twitter: [https://twitter.com/yourusername]
    LinkedIn: [https://linkedin.com/in/yourusername]
"""


# Set up logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)

def load_config(config_file="config.yaml"):
    """
    Load configuration from a YAML file.
    """
    try:
        logging.info(f"Loading configuration from '{config_file}'")
        with open(config_file, "r") as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logging.error(f"Configuration file '{config_file}' not found.")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file: {e}")
        raise

def read_file_lines(file_path):
    """
    Read and return lines from a text file.
    """
    try:
        logging.info(f"Reading file: {file_path}")
        with open(file_path, "r", encoding="utf-8") as file:
            lines = [line.strip() for line in file.readlines()]
        logging.info(f"Loaded {len(lines)} lines from {file_path}")
        return lines
    except Exception as e:
        logging.error(f"Error reading file '{file_path}': {e}")
        raise

def sanitize_ip(ip_with_port):
    """
    Sanitize an IP address by removing ports and trimming whitespace.

    Args:
        ip_with_port (str): The IP address potentially with a port (e.g., '192.168.1.1:443').

    Returns:
        str: The sanitized IP address without port and whitespace.
    """
    # Trim whitespace
    sanitized_ip = ip_with_port.strip()

    # Remove port if present
    if ":" in sanitized_ip:
        sanitized_ip = sanitized_ip.split(":")[0]

    return sanitized_ip

def find_breaches(breach_ips, org_cidrs, org_ips):
    """
    Match breached IPs against org CIDRs and IPs.
    """
    breached_results = {"in_cidr": [], "in_ip_list": []}

    logging.info("Starting IP match checks...")
    for breach_ip in breach_ips:
        try:
            # Sanitize the IP
            sanitized_ip = sanitize_ip(breach_ip)

            # Validate the sanitized IP
            ip = ipaddress.ip_address(sanitized_ip)
            logging.debug(f"Checking sanitized breach IP: {sanitized_ip}")

            # Check against CIDRs
            for cidr in org_cidrs:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    logging.info(f"IP {sanitized_ip} found in CIDR {cidr}")
                    breached_results["in_cidr"].append(sanitized_ip)

            # Check against org IP list
            if sanitized_ip in org_ips:
                logging.info(f"IP {sanitized_ip} found in org IP list")
                breached_results["in_ip_list"].append(sanitized_ip)

        except ValueError:
            logging.warning(f"Invalid breach IP skipped: {breach_ip}")

    return breached_results


def process_files(config, breach_files=None, cidr_files=None, ip_files=None):
    """
    Process breach, CIDR, and IP files and write results to JSON.
    """
    breach_dir = config["defaults"]["breach_lists_dir"]
    cidr_dir = config["defaults"]["org_cidr_lists_dir"]
    ip_dir = config["defaults"]["org_ip_lists_dir"]
    output_dir = config["defaults"]["output_dir"]
    recursive = config["defaults"]["recursive"]

    # Get all files if specific files are not provided
    breach_files = breach_files or get_all_files(breach_dir, recursive)
    cidr_files = cidr_files or get_all_files(cidr_dir, recursive)
    ip_files = ip_files or get_all_files(ip_dir, recursive)

    logging.info(f"Processing {len(breach_files)} breach files")
    logging.info(f"Processing {len(cidr_files)} CIDR files")
    logging.info(f"Processing {len(ip_files)} IP files")

    # Read data from files
    all_breach_ips = [ip for file in breach_files for ip in read_file_lines(file)]
    all_cidrs = [cidr for file in cidr_files for cidr in read_file_lines(file)]
    all_ips = [ip for file in ip_files for ip in read_file_lines(file)]

    logging.info(f"Loaded {len(all_breach_ips)} breach IPs")
    logging.info(f"Loaded {len(all_cidrs)} CIDRs")
    logging.info(f"Loaded {len(all_ips)} org IPs")

    # Find matches
    results = find_breaches(all_breach_ips, all_cidrs, all_ips)

    # Write results to JSON
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "breach_results.json")
    with open(output_file, "w") as json_file:
        json.dump(results, json_file, indent=4)
    logging.info(f"Results written to {output_file}")

def get_all_files(directory, recursive=True):
    """
    Get all text files from a directory, optionally recursively.
    """
    logging.info(f"Searching for files in directory: {directory}")
    if recursive:
        return [
            os.path.join(root, file)
            for root, _, files in os.walk(directory)
            for file in files if file.endswith(".txt")
        ]
    else:
        return [
            os.path.join(directory, file)
            for file in os.listdir(directory)
            if file.endswith(".txt")
        ]

def parse_arguments():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(description="Check breached IPs against org data.")
    parser.add_argument("--breach_files", nargs="*", help="Specific breach list files to check")
    parser.add_argument("--cidr_files", nargs="*", help="Specific CIDR list files")
    parser.add_argument("--ip_files", nargs="*", help="Specific IP list files")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()

def main():
    """
    Main function to execute the script.
    """
    # Load config
    config = load_config()

    # Parse arguments
    args = parse_arguments()

    # Set logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    logging.info("Starting breach check process...")
    process_files(
        config,
        breach_files=args.breach_files,
        cidr_files=args.cidr_files,
        ip_files=args.ip_files,
    )
    logging.info("Breach check process completed.")

if __name__ == "__main__":
    main()
