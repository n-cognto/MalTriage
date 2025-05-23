# MalTriage

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-brightgreen.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

A comprehensive Python-based file triaging tool for analyzing suspicious files, featuring:

- **Static Analysis**: Examine file properties without execution
- **Dynamic Analysis**: Observe runtime behavior in a controlled environment
- **Heuristic & Signature-based Detection**: Match against known patterns
- **Machine Learning-based Classification**: Predict maliciousness using AI
- **Archive Analysis**: Safely extract and analyze compressed file contents

## Overview

MalTriage is a powerful yet flexible tool designed to help security analysts, malware researchers, and incident responders quickly analyze potentially malicious files. By combining multiple analysis techniques, it provides a comprehensive assessment of file safety with minimal setup requirements.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Architecture](#architecture)
- [Output Examples](#output-examples)
- [Extending MalTriage](#extending-maltriage)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License & Disclaimer](#license--disclaimer)
- [Credits](#credits)

## Features

### Static Analysis
- File metadata extraction (name, size, type)
- Comprehensive hash calculation (MD5, SHA1, SHA256)
- Shannon entropy calculation for file and sections
- PE header analysis for Windows executables
  - Section properties and anomalies
  - Import/Export tables
  - Resources and entry points
- String extraction with suspicious pattern matching
- URL and IP address detection

### Dynamic Analysis
- Safe execution monitoring in a controlled environment
- Real-time network activity tracking (connections, ports, protocols)
- Process creation and relationship monitoring
- File system operation tracking
- Registry change detection (Windows)
- Basic sandbox capabilities with configurable timeout
- Extensibility for integration with Cuckoo Sandbox

### Archive Analysis
- Detection and identification of common archive formats (ZIP, TAR, RAR, 7z)
- Safe extraction with protection against archive-based attacks
- Detailed inventory of archive contents
- Recursive analysis of files within archives
- Built-in security measures:
  - Zip/Tar bomb protection
  - Path traversal attack prevention
  - Size and resource limits
  - Automatic cleanup of temporary files

### Heuristic & Signature Detection
- Hash-based matching against known malware databases
- Regular expression pattern matching for malicious indicators
- YARA rule support for custom detection rules
- PE anomaly detection (high entropy sections, suspicious APIs)
- Behavioral indicators of compromise (IOCs)

### Machine Learning Detection
- Automated feature extraction from static and dynamic analysis
- Random Forest classifier for malicious file detection
- Probability scoring with confidence levels
- Feature importance analysis for explainable results
- Synthetic training data generation for demonstration
- Support for custom model training

## Installation

### Prerequisites
- Python 3.8 or higher
- Required Python packages (specified in requirements.txt)
- Linux, macOS, or Windows operating system
- Sufficient privileges to install packages

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/maltriage.git
cd maltriage
```

2. Create and activate a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run initial setup to create default files:
```bash
python main.py --setup
```

### Optional Components

For enhanced functionality, you may want to install:

- **Cuckoo Sandbox**: For advanced dynamic analysis
  ```bash
  # Follow instructions at https://cuckoo.sh/docs/
  ```

- **YARA**: For advanced pattern matching
  ```bash
  pip install yara-python
  ```

- **Additional ML Models**: For specialized detection
  ```bash
  # Place custom models in the 'model' directory
  ```

## Usage

### Basic Usage

Analyze a single file:

```bash
python main.py analyze /path/to/suspicious/file
```

Analyze all files in a directory:

```bash
python main.py batch /path/to/suspicious/directory
```

### Command Line Arguments

#### Single File Analysis

```
python main.py analyze [-h] [--no-dynamic] [--timeout TIMEOUT] [--sandbox {safe,vm}] [--output {json,txt}] [--recursive] file_path
```

Arguments:
- `file_path`: Path to the file to analyze
- `--no-dynamic`: Disable dynamic analysis
- `--timeout TIMEOUT`: Timeout for dynamic analysis in seconds (default: 60)
- `--sandbox {safe,vm}`: Sandbox type for dynamic analysis (default: safe)
- `--output {json,txt}`: Output format for the report (default: json)
- `--recursive`: Recursively analyze contents of archive files

#### Batch Analysis

```
python main.py batch [-h] [--output-dir OUTPUT_DIR] [--no-dynamic] [--timeout TIMEOUT] [--sandbox {safe,vm}] directory
```

Arguments:
- `directory`: Directory containing files to analyze
- `--output-dir OUTPUT_DIR`: Directory to save reports
- `--no-dynamic`: Disable dynamic analysis
- `--timeout TIMEOUT`: Timeout for dynamic analysis in seconds (default: 30)
- `--sandbox {safe,vm}`: Sandbox type for dynamic analysis (default: safe)

### Advanced Usage Examples

```bash
# Analyze a specific file with extended dynamic analysis timeout
python main.py analyze /path/to/suspicious.exe --timeout 180 --output txt

# Analyze a compressed file and its contents
python main.py analyze /path/to/suspicious.zip --recursive

# Batch analyze files without dynamic analysis and custom output directory
python main.py batch /path/to/samples/ --no-dynamic --output-dir /path/to/reports/

# Analyze a file using VM-based sandbox (requires Cuckoo integration)
python main.py analyze /path/to/suspicious.dll --sandbox vm

# Analyze a file with spaces in filename
python main.py analyze "/path/to/file with spaces.pdf"
```

### Working with Archive Files

MalTriage supports analysis of common archive formats:

1. **Basic Analysis**: Analyze an archive like any other file
   ```bash
   python main.py analyze archive.zip
   ```
   This provides metadata, hashes, and information about the archive structure.

2. **Recursive Analysis**: Analyze both the archive and its contents
   ```bash
   python main.py analyze archive.zip --recursive
   ```
   This extracts files (with security checks) and analyzes each extracted file.

3. **Output Format**: For detailed reports, use the text format
   ```bash
   python main.py analyze archive.zip --recursive --output txt
   ```

The archive analysis provides:
- Archive type identification
- File inventory with sizes and hashes
- Analysis of archive structure
- Identification of potentially malicious files within archives
- Protection against common archive-based attacks

## Architecture

MalTriage is built with a modular architecture that separates concerns and allows for easy extension:

```
maltriage/
├── analyzer/
│   ├── static_analyzer.py   # Static file analysis and archive handling
│   ├── dynamic_analyzer.py  # Execution monitoring
│   ├── heuristics.py        # Signature-based detection
│   └── ml_detector.py       # Machine learning classification
├── samples/                 # Sample files for analysis
├── signatures/              # Signature databases and YARA rules
├── model/                   # ML models
├── reports/                 # Generated analysis reports
├── main.py                  # Main integration and CLI
└── requirements.txt         # Dependencies
```

## Output Examples

### JSON Report Structure

```json
{
  "file": "/path/to/sample.exe",
  "analysis_time": "2025-05-23T14:30:45.123456",
  "static_analysis": {
    "file_info": { "name": "sample.exe", "size": 245760 },
    "hashes": { "md5": "a1b2c3...", "sha1": "d4e5f6...", "sha256": "1a2b3c..." },
    "entropy": 7.2,
    "pe_data": { /* PE header analysis results */ },
    "suspicious_strings": [ /* detected suspicious strings */ ]
  },
  "dynamic_analysis": {
    "network_activity": [ /* detected connections */ ],
    "process_activity": [ /* created processes */ ],
    "file_operations": [ /* file system operations */ ]
  },
  "heuristic_analysis": {
    "verdict": "suspicious",
    "score": 65,
    "hash_matches": [ /* matched signatures */ ],
    "string_matches": [ /* matched string patterns */ ],
    "yara_matches": [ /* matched YARA rules */ ]
  },
  "ml_analysis": {
    "prediction": "malicious",
    "probability": 0.89,
    "features_used": [ /* features used by ML model */ ]
  },
  "overall_verdict": {
    "verdict": "malicious",
    "confidence_score": 78.5
  }
}
```

### Archive Analysis Example

```json
{
  "file_type": "archive-zip",
  "archive_analysis": {
    "archive_type": "zip",
    "num_files": 25,
    "files": [
      {
        "name": "document.pdf",
        "path": "folder/document.pdf",
        "size": 245760,
        "md5": "a1b2c3...",
        "extension": ".pdf"
      }
    ]
  },
  "child_analyses": [
    {
      "path_in_archive": "folder/document.pdf",
      "analysis": {
        /* Complete analysis results for this file */
      }
    }
  ]
}
```

### Text Report Sample

```
MALTRIAGE REPORT
==============

File: /path/to/sample.exe
Analysis Time: 2025-05-23T14:30:45.123456
Overall Verdict: MALICIOUS (Confidence: 78.50%)

KEY FINDINGS
------------
Hash Matches:
  - md5: Known Trojan.Example
YARA Matches:
  - example_malware: Example YARA rule for demonstration
Suspicious Strings:
  - This is an example malicious string
  - botnet command and control
  - ... (3 more)
Network Activity:
  - 192.168.1.100:49152 -> 203.0.113.1:80
  - ... (2 more connections)

... (rest of the report)
```

## Extending MalTriage

### Adding Custom Signatures

1. Edit or add hash-based signatures in `signatures/known_signatures.json`:

```json
{
  "hash_signatures": [
    {
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "description": "Known malware sample XYZ",
      "threat_name": "Trojan.GenericXYZ"
    }
  ],
  "string_signatures": [
    {
      "pattern": "(?i)suspicious_string_pattern",
      "description": "Remote access functionality",
      "threat_name": "Generic.RAT"
    }
  ]
}
```

2. Add custom YARA rules in `signatures/rules.yar`:

```yara
rule custom_malware_detection {
    meta:
        description = "Detects specific malware family"
        author = "Your Name"
        date = "2025-05"
        threat_level = "high"
    strings:
        $a = "unique string pattern" nocase
        $b = { 4D 5A 90 00 03 00 00 00 }
        $pdb = /\\Project\\Release\\malware\.pdb/
    condition:
        uint16(0) == 0x5A4D and ($a or $b) and $pdb
}
```

### Training the ML Model

The system comes with a pre-trained model using synthetic data. To train on your own samples:

```python
from analyzer.ml_detector import MalwareDetector

# Initialize detector with path to save the model
detector = MalwareDetector("path/to/custom_model.pkl")

# Prepare your training data
training_data = []  # List of static and dynamic analysis results
labels = []         # 0 for benign, 1 for malicious

# Train the model
result = detector.train(training_data, labels)
print(f"Training accuracy: {result['metrics']['accuracy']}")
```

### Integration with Cuckoo Sandbox

The dynamic analyzer includes a placeholder class for Cuckoo integration. To fully integrate:

1. Install and configure Cuckoo Sandbox
2. Update the CuckooIntegration class in dynamic_analyzer.py:

```python
def submit_sample(self, file_path):
    import requests
    with open(file_path, 'rb') as sample:
        files = {'file': (os.path.basename(file_path), sample)}
        response = requests.post(
            f"{self.api_url}/tasks/create/file",
            files=files
        )
        return response.json()
```

3. Use the 'vm' sandbox option when running analysis:
```bash
python main.py analyze suspicious_file.exe --sandbox vm
```

## Security Considerations

**⚠️ WARNING ⚠️**

This tool is designed for analysis in a controlled environment. Consider the following:

1. **Isolated Environment**: Always run in an isolated virtual machine or container
2. **Network Isolation**: Disable internet access during analysis or use a controlled network
3. **Permissions**: Do not run the tool with elevated privileges unless necessary
4. **Data Handling**: Treat all analyzed files as potentially malicious
5. **Safe Storage**: Store malware samples securely with appropriate access controls

### Archive-Specific Security Concerns

When analyzing archive files, be especially careful:

1. **Zip/Tar Bombs**: MalTriage includes protection against decompression bombs, but extremely large archives may be rejected
2. **Path Traversal**: The tool prevents path traversal attacks that could escape the extraction directory
3. **Resource Management**: Analysis is limited to a configurable number of files per archive to prevent resource exhaustion
4. **Dynamic Analysis**: By default, extracted files are not executed in dynamic analysis as a safety precaution

Dynamic analysis can execute potentially malicious code. Never use this tool on production systems or personal devices without proper isolation.

## Contributing

Contributions are welcome! Please consider the following:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and ensure code quality
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Quality Guidelines

- Follow PEP 8 style guidelines for Python code
- Add appropriate comments and documentation
- Write tests for new features
- Ensure backward compatibility when possible

## License & Disclaimer

This project is licensed under the MIT License - see the LICENSE file for details.

**Disclaimer**: This tool is provided for educational and research purposes only. The authors are not responsible for any damage caused by the misuse of this tool or the malware samples it may analyze.

## Credits

- Developed by: [Your Name]
- Date: May 2025
- Contact: your.email@example.com
- Special thanks to: [Contributors and acknowledgments]

---

*MalTriage - Making malware analysis accessible and efficient.*