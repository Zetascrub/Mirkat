import os

# Basic project settings
PROJECT_DIR = "Projects"
DEFAULT_LOG_DIR = "Logs"
VULNERABILITY_DETAILS_FILE = os.path.join("Core", "vulnerability_details.json")
VULNERABILITY_DATASET_FILE = os.path.join("Core", "vulnerability_dataset.json")

# Define the path for the scope file if used across the application
SCOPE_FILE_PATH = os.path.join(PROJECT_DIR, "scope.txt")

# Directory structure for scan results
SCAN_RESULTS_DIR_NAME = "Scans"
REPORTS_DIR_NAME = "Reports"
SSL_SCAN_DIR_NAME = "SSLScan"

# Output and reporting settings
EXCEL_REPORT_FILENAME = "scan_report.xlsx"
HTML_REPORT_FILENAME = "scan_summary.html"

# Tool paths and settings (example for external tools that might be called)
NMAP_PATH = "/usr/bin/nmap"
SSLSCAN_PATH = "/usr/bin/sslscan"

# API Configurations (example for any API integrations)
LLAMA_API_HOST = "http://127.0.0.1:11434"
LLAMA_API_KEY = "your_llama_api_key_here"

# Security settings, e.g., for HTTPS verification
VERIFY_SSL = False

# Add any other global settings or constants
# For example, severity levels for vulnerabilities
SEVERITY_LEVELS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0
}

# You can also include functions for commonly used configurations
def get_full_path(relative_path):
    """Returns the full path based on the project directory."""
    current_dir = os.getcwd()
    return os.path.join(current_dir, relative_path)
