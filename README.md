# Breach Check

A script to check breached IPs against organizational CIDR ranges and IP lists. It processes input files recursively or specific files as defined by command-line arguments, sanitizes IPs, and outputs matched results to a JSON file.

---

## Features

- Recursively processes input files from predefined directories.
- Sanitizes and validates IP addresses (trims whitespace, removes ports).
- Matches IPs against CIDR ranges and IP lists.
- Outputs results to a JSON file in the specified output directory.

---

## File Structure

- **`config.yaml`**: Defines default directories and behavior for the script.
- **`breach_lists/`**: Contains breach IP list files.
- **`org_cidr_lists/`**: Contains organization CIDR list files.
- **`org_ip_lists/`**: Contains organization IP list files.
- **`output/`**: Stores the results JSON file (ignored by Git using `.gitignore`).
- **`requirements.txt`**: Lists required Python libraries for installation.

---

## Setup

1. Clone the repository:
    ```bash
    git clone https://github.com/BadSamuraiDev/breach_check.git
    ```
2. Navigate to the project directory:
    ```bash
    cd your-repository
    ```
3. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
4. Edit `config.yaml` to customize input/output directories and behavior.

---

## Usage

### Sample

The script contains sample org files from the FortiNet Belsen Leak found on the repo by [arsolutioner](https://github.com/arsolutioner/fortigate-belsen-leak/blob/main/affected_ips.txt). These files can simply be removed and replaced with your own.

### Run the Script
```bash
python breach_check.py [--breach_files FILE ...] [--cidr_files FILE ...] [--ip_files FILE ...] [--debug]

### Output Sample

```json
{
    "in_cidr": [
        "72.27.4.3",
        "175.45.29.190"
    ],
    "in_ip_list": [
        "63.143.98.183",
        "175.45.29.190"
    ]
}
```