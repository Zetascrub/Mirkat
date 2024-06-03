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

    def print_banner(self):
        banner = """
        *****************************************
        *            Scan Started               *
        *****************************************
        """
        print(banner)

    def print_error(self, message):
        self.log_message(message, logging.ERROR)
        self.print_colored(message, "High")

    def print_info(self, title, message):
        full_message = f"{title}: {message}"
        self.log_message(full_message, logging.INFO)
        print(full_message)

# Example of instantiating and using OutputManager
if __name__ == "__main__":
    output_manager = OutputManager()
    output_manager.print_banner()
    output_manager.print_info("This is an informational message.")
    output_manager.print_error("This is an error message.")
