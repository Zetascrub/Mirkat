
# Mirkat: Automated Vulnerability Scanning Tool

## Overview

Mirkat is an automated scanning tool designed to simplify the process of vulnerability detection and management. It integrates multiple scanning techniques, including Nmap and SSL scanning, to provide comprehensive security assessments. Mirkat is highly configurable and can be extended with custom plugins to meet specific needs.

## Features

- **Nmap Scanning**: Utilizes Nmap to perform detailed network scans.
- **SSL Scanning**: Checks for SSL/TLS misconfigurations and vulnerabilities.
- **Vulnerability Management**: Manages and updates vulnerability data.
- **Report Generation**: Generates detailed reports in Excel and HTML formats.
- **Customizable Plugins**: Extend functionality with custom plugins.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/mirkat.git
    cd mirkat
    ```

2. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Configuration

Configuration settings are located in `config.py`. Update the settings as necessary for your environment.

Key settings include:
- `PROJECT_DIR`: Directory for project files.
- `NMAP_PATH`: Path to the Nmap executable.
- `SSLSCAN_PATH`: Path to the SSLScan executable.
- API configurations, logging settings, and more.

## Usage

### Command Line Interface

Run Mirkat using the command line interface:
```sh
python mirkat.py -p <project_code> -c <client_name> -s <scope> [-l <llm_ip>]

    -p, --project_code: The project code.
    -c, --client_name: The client's name.
    -s, --scope: The target IP/URL or a file containing a list of targets.
    -l, --llm: (Optional) IP of the Ollama API.
```

### Example

```sh

python mirkat.py -p PROJ123 -c "Client Name" -s "192.168.1.1, 192.168.1.2" -l "127.0.0.1:11434"
```

## Project Structure

Mirkat organizes output and reports into a structured directory format:

    Scans/: Contains scan results.
    Reports/: Contains generated reports.


## Development

## Extending Mirkat with Plugins

Custom plugins can be added to the Scanners directory. Plugins should inherit from the PluginBase class and implement the run method.

Example plugin structure:

```python

from Core.plugin_base import PluginBase

class CustomScanner(PluginBase):
    def run(self):
        # Custom scanning logic here
        pass
```


Key Modules

    mirkat.py: Main entry point for the tool.
    config.py: Configuration settings.
    nmap_scanner.py: Nmap scanning logic.
    ssl_scanner.py: SSL scanning logic.
    vuln_manager.py: Manages vulnerabilities.
    report_generator.py: Generates reports.
    output_manager.py: Manages logging and output.

# Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes.

# License

This project is licensed under the MIT License. See the LICENSE file for more details.

# Contact

For questions or support, please open an issue on the GitHub repository or contact Thomas.e.odonnell@gmail.com.