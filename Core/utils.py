import os
import logging
from Core.config import DEFAULT_LOG_DIR

def setup_logging(log_file_name="app.log", level=logging.INFO):
    log_dir = os.path.join(DEFAULT_LOG_DIR)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    logging.basicConfig(filename=os.path.join(log_dir, log_file_name),
                        filemode='a',
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        level=level)

def print_banner():
    banner_text = """
    ##########################################################
    #                                                        #
    #  Automated Scanning Tool - Welcome                     #
    #                                                        #
    ##########################################################
    """
    print(banner_text)

def is_valid_ip(ip_address):
    import socket
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error:
        return False

def read_scope_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        logging.error(f"Scope file not found: {file_path}")
        return []

def convert_severity_to_color(severity):
    severity_colors = {
        "High": "\033[91m",  # Red
        "Medium": "\033[93m",  # Yellow
        "Low": "\033[96m",  # Cyan
        "Info": "\033[94m",  # Blue
    }
    return severity_colors.get(severity, "\033[0m")  # Default to no color

def get_full_path(relative_path):
    """Returns the full path based on the project directory."""
    current_dir = os.getcwd()
    return os.path.join(current_dir, relative_path)
