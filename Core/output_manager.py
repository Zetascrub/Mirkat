import logging
from Core.utils import convert_severity_to_color, setup_logging

class OutputManager:
    def __init__(self, log_file='application.log'):
        setup_logging(log_file_name=log_file)
        self.log_file = log_file

    def log_message(self, message, level=logging.INFO):
        if level == logging.DEBUG:
            logging.debug(message)
        elif level == logging.INFO:
            logging.info(message)
        elif level == logging.WARNING:
            logging.warning(message)
        elif level == logging.ERROR:
            logging.error(message)
        elif level == logging.CRITICAL:
            logging.critical(message)

    def print_colored(self, message, severity='Info'):
        color = convert_severity_to_color(severity)
        reset_color = "\033[0m"
        print(f"{color}{message}{reset_color}")

    def print_banner(self, message="Scan Started"):
        banner = f"""
        *****************************************
        *            {message}               *
        *****************************************
        """
        self.print_colored(banner, 'Info')

    def print_divider(self):
        print("\n" + "="*50 + "\n")

    def print_info(self, title, message):
        formatted_message = f"{title}: {message}"
        self.log_message(formatted_message, logging.INFO)
        self.print_colored(formatted_message, 'Info')

    def print_success(self, message):
        self.print_colored(message, 'Info')

    def print_warning(self, message):
        self.print_colored(message, 'Warning')

    def print_error(self, message):
        self.log_message(message, logging.ERROR)
        self.print_colored(message, "High")
