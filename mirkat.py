import os
import argparse
from colorama import Fore, Style
import json
import shutil
import subprocess
import re


def load_config(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

class OutputManager:
    def __init__(self):
        # Load configuration
        self.config = load_config('config.json')
        self.log_dir = self.config["output"]["path"]
        self.log_file_path = os.path.join(self.log_dir, "output_log.txt")
        self.title_width = self.config["output"]["title_width"]
        self.message_width = self.config["output"]["message_width"]

    def log_message(self, message):
        with open(self.log_file_path, 'a') as log_file:
            log_file.write(message + "\n")
    
    def print_banner(self):
        ascii_art = """
                      ,'''''-._
                     ;  ,.  <> `-._ 
                     ;  \'   _,--'"
                    ;      (
                    ; ,   ` \\
                    ;, ,     \\
                   ;    |    |
                   ; |, |    |\\
                  ;  |  |    | \\
                  |.-\\ ,\\    |\\ :
                  |.- `. `-. | ||
                  :.-   `-. \\ ';;
                   .- ,   \\;;|
        """
        # print(ascii_art)
        centered_banner = (Fore.YELLOW + f"{ascii_art}\n\t\tM.I.R.K.A.T" + Style.RESET_ALL).center(self.title_width)
        print(centered_banner)
        

    def print_title(self, title):
        centered_title = (Fore.MAGENTA + f"--=={title}==--" + Style.RESET_ALL).center(self.title_width)
        print(centered_title)

    def print_info(self, title, message):
        formatted_title = (Fore.CYAN + title + Style.RESET_ALL).ljust(self.title_width)
        formatted_message = (Fore.LIGHTBLUE_EX + message + Style.RESET_ALL).ljust(self.message_width)
        print(f"{formatted_title}: {formatted_message}")
        self.log_message(f"{title}: {message}")

    def print_error(self, title, message):
        formatted_title = (Fore.RED + title + Style.RESET_ALL).ljust(self.title_width)
        formatted_message = (Fore.LIGHTRED_EX + message + Style.RESET_ALL).ljust(self.message_width)
        print(f"{formatted_title}: {formatted_message}")
        self.log_message(f"{title}: {message}")

    def send_notification(self, message, level='info'):
        # Send notifications using a tool like ntfy
        # Implement the logic to send a notification based on the level (info, error, etc.)
        pass

class ConfigManager():
    
    def __init__(self):
        self.config_path = "config.json"
        if not os.path.exists(self.config_path):
            # Create an empty configuration file if not present
            with open(self.config_path, 'w') as config_file:
                json.dump({}, config_file, indent=4)
        self.config = self.read_config()

        if 'mirkat' not in self.config:
            default_config = {
                "root_dir": "",
                "path": "",
                "title_width": 50,
                "message_width": 50
            }
            self.config['mirkat'] = default_config
            self.save_config(self.config)
            self.config = self.read_config()

    def read_config(self):
        with open(self.config_path, 'r') as config_file:
            config = json.load(config_file)
            return config

    def save_config(self, new_config):
        with open(self.config_path, 'w') as config_file:
            json.dump(new_config, config_file, indent=4)


# log_directory = "."  # Adjust the path as needed
output = OutputManager()
config = ConfigManager()

# Tools

class NmapScans:

    def __init__(self, targets, project_dir):
        # Class Calls
        self.output = OutputManager()
        self.config = config.read_config()
        # Class Settings
        self.targets = targets
        self.class_name = "Nmap"
        self.root_dir = project_dir
        self.results = {}
        self.ports = []
        self.http_services = []  # Initialize as a dictionary
        
        # Create Directory

        # Additonal Settings
        tools_required = ["nmap"]
        check_tool_availability(self.class_name, tools_required, self.root_dir)    

        # Check if 'nmap' key exists in config, add default values if not
        default_config = {
            "scan_type": {
                "fast_tcp_scan_command": "nmap -p 0-65535 -T4 --open -oX",
                "detailed_tcp_scan_command": "nmap -p 80 -sV -oN",
                "udp_scan_command": "nmap -sU --top-ports 100 -oN"
            },
            "verbose": 1,
            "output_type": "xml"
        }
        
        if 'nmap' not in self.config:
            self.config['nmap'] = default_config
            # Optionally, save the updated config back to the file
            with open('config.json', 'w') as config_file:
                json.dump(self.config, config_file, indent=4)


            self.config['nmap'] = default_config
            ConfigManager().save_config(self.config)
            self.config = ConfigManager().read_config()   


    def perform_scan(self):
        for scan_type in self.config["nmap"]["scan_type"]:
            nmap_command_template = self.config["nmap"]["scan_type"][scan_type]
            for target in self.targets:
                output.print_info(f"Nmap {scan_type} Scan on {target}", "Started")
                nmap_output_file_path = os.path.join(self.root_dir, "Scans/Nmap", f"{target}_{scan_type}_scan.txt")

                # Construct nmap command based on whether ports are specified
                if len(self.ports) >= 1:
                    ports_str = ",".join(port.split('/')[0] for port in self.ports if '/' in port)                    
                    output.print_info("Scanning specific ports:",f"{ports_str}")
                    nmap_command = f"{nmap_command_template} {nmap_output_file_path} -p {ports_str} {target}"
                else:
                    output.print_info("Scanning all ports","")
                    nmap_command = f"{nmap_command_template} {nmap_output_file_path} -p 0-65535 {target}"
                # Parse the output file to update self.ports
                # self.parse_nmap_output(nmap_output_file_path)

                output.log_message(f"Command Ran: {nmap_command}")
                self._execute_scan(nmap_command, nmap_output_file_path, target, scan_type)
                output.print_info(f"Nmap {scan_type} Scan on {target}", "Completed")
                self._parse_file(nmap_output_file_path, target)


    def _execute_scan(self, nmap_command, output_file_path, target, scan_type):
        try:
            with open(output_file_path, 'w') as output_file:
                subprocess.run(nmap_command, shell=True, stdout=output_file, stderr=subprocess.STDOUT)
        except subprocess.SubprocessError as error:
            output.print_error(f"Error during {scan_type} Nmap scan on {target}", error)


    def parse_results(self):
        for file_name in os.listdir(os.path.join(self.root_dir, "Scans/Nmap")):
            file_path = os.path.join(self.root_dir, "Scans/Nmap", file_name)
            target, scan_type = self._extract_target_and_scan_type(file_name)
            self._initialize_target_in_results(target)
            self._parse_file(file_path, target)

    def _parse_file(self, file_path, target):
        with open(file_path, 'r') as file:
            for line in file:
                if "/tcp" in line and "open" in line:
                    self._extract_service_info(line, target, 'tcp')
                elif "/udp" in line and "open" in line:
                    self._extract_service_info(line, target, 'udp')

    def _extract_target_and_scan_type(self, file_name):
        # Extracts target and scan type from the file name
        parts = file_name.split("_")
        target = parts[0]
        scan_type = parts[1]
        return target, scan_type

    def _extract_service_info(self, line, target, protocol):
        if target not in self.results:
            self.results[target] = {}
        parts = line.split()
        port = parts[0]
        self.ports.append(port)
        service = parts[2] if len(parts) >= 3 else "unknown"
        self.results[target].setdefault(protocol, {})[port] = service
        if service in ['http', 'https']:
            url = f"{service}://{target}:{port.split('/')[0]}"
            output.print_info("HTTP Service Found", f"{url}")
            self.http_services.append(url)

    def print_results(self):
        output.print_title("Nmap Results")
        for target, ports in self.results.items():
            self._print_target_results(target, ports)

    def _print_target_results(self, target, ports):
        output.print_info(f"Target:", target)
        self._print_protocol_results(ports, 'tcp')
        self._print_protocol_results(ports, 'udp')

    def _print_protocol_results(self, ports, protocol):
        output.print_info(f"Open {protocol.upper()}", "")
        for port, service in ports.get(protocol, {}).items():
            output.print_info(f"{port}", f"{service}")

    def _initialize_target_in_results(self, target):
        # Initialize target in self.results if not already present
        if target not in self.results:
            self.results[target] = {'tcp': {}, 'udp': {}}

class EyeWitnessScans():
    def __init__(self, project_dir, http_services):
        self.config = load_config('config.json')
        self.root_dir = project_dir
        self.http_services = http_services
        self.eyewitness_output_dir = os.path.join(self.root_dir, "Scans/EyeWitness")

    def run_scan(self):
        self._create_output_directory()
        urls_file_path = self._write_http_services_to_file()
        self._execute_eyewitness_scan(urls_file_path)

    def _create_output_directory(self):
        # Ensure the EyeWitness output directory exists
        os.makedirs(self.eyewitness_output_dir, exist_ok=True)

    def _write_http_services_to_file(self):
        # Write the HTTP/HTTPS services to a file
        urls_file_path = os.path.join(self.root_dir, "http_services.txt")
        with open(urls_file_path, 'w') as file:
            for url in self.http_services:
                file.write(url + "\n")
        return urls_file_path

    def _execute_eyewitness_scan(self, urls_file_path):
        # Construct and run the EyeWitness command
        eyewitness_command = f"eyewitness --web -f {urls_file_path} --no-prompt -d {self.eyewitness_output_dir}"
        output.log_message(f"Command Ran: {eyewitness_command}")

        try:
            output.print_info("EyeWitness", "Started")
            with open(os.devnull, 'w') as devnull:
                subprocess.run(eyewitness_command, shell=True, stdout=devnull, stderr=subprocess.STDOUT)
            output.print_info("EyeWitness", "Completed.")
        except subprocess.SubprocessError as error:
            output.print_error(f"Error running EyeWitness:", error)

class SSLScans:
    def __init__(self, project_dir, targets):
        self.config = load_config('config.json')
        self.root_dir = project_dir
        self.targets = targets
        self.results = {}


    def perform_scan(self):
        for target in self.targets:
            target = target.replace("http://","").replace("https://","")
            output_file_path = self._prepare_output_file_path(target)
            # Construct SSLScan command
            ssl_scan_command = f"sslscan --no-colour {target}"
            output.log_message(f"Command Ran: {ssl_scan_command}")

            self._execute_ssl_scan(ssl_scan_command, output_file_path, target)

    def _prepare_output_file_path(self, target):
        # Remove 'http://' or 'https://' from the target
        target = target.replace("http://", "").replace("https://", "")
        
        # Replace ':' with an alternative character, like '-'
        target = target.replace(":", "-")
        
        return os.path.join(self.root_dir, "Scans/SSLscan", f"{target}_ssl_scan.txt")


    def _execute_ssl_scan(self, ssl_scan_command, output_file_path, target):
        # Execute the SSL scan command
        try:
            output.print_info(f"SSLScan:", target)
            with open(output_file_path, 'w') as output_file:
                subprocess.run(ssl_scan_command, shell=True, stdout=output_file, stderr=subprocess.STDOUT)
        except subprocess.SubprocessError as error:
            output.print_error(f"Error during SSL scan on {target}:", error)

    def parse_results(self):
        for target in self.targets:
            output_file_path = self._prepare_output_file_path(target)
            self.results[target] = {'protocols': [], 'vulnerabilities': []}
            self._parse_ssl_scan_results(output_file_path, target)

    def _parse_ssl_scan_results(self, file_path, target):
        # Parse the results of the SSL scan
        try:
            with open(file_path, 'r') as file:
                content = file.read()
                self._extract_ssl_scan_info(content, target)
        except IOError as error:
            output.print_error(f"Error reading file {file_path}",f"{error}")

    def _extract_ssl_scan_info(self, content, target):
        # Extract information from the SSL scan content
        protocols = re.findall(r'Protocol: (.*?)\n', content)
        vulnerabilities = re.findall(r'Vulnerability: (.*?)\n', content)
        self.results[target]['protocols'] = protocols
        self.results[target]['vulnerabilities'] = vulnerabilities

    def print_results(self):
        output.print_title("SSL Scan Results")
        for target, result in self.results.items():
            self._print_target_results(target, result)

    def _print_target_results(self, target, result):
        # Print results for a specific target
        output.print_info(f"Target:", f"{target}")
        self._print_scan_details("Supported Protocols", result['protocols'])
        self._print_scan_details("Vulnerabilities", result['vulnerabilities'])

    def _print_scan_details(self, category, details):
        # Print details of a specific category (protocols or vulnerabilities)
        
        for detail in details:
            output.print_info(f"{category}:", f"{detail}")

def execute_scans(scope, project_dir):

    # Nmap Scans
    output.print_title("Nmap")
    nmap_scanner = NmapScans(scope, project_dir)
    # nmap_scanner.perform_scan()
    # for scan_type in ["fast_tcp", "detailed_tcp", "udp"]:
    #     nmap_scanner.perform_scan(scan_type)
    nmap_scanner.perform_scan()
    nmap_scanner.parse_results()
    nmap_scanner.print_results()

    # EyeWitness Scans
    http_services = nmap_scanner.http_services
    if http_services:
        output.print_title("EyeWitness")
        eyewitness_scanner = EyeWitnessScans(project_dir, http_services)
        eyewitness_scanner.run_scan()

    # SSL Scans
    if http_services:
        output.print_title("TestSSL")
        ssl_scanner = SSLScans(project_dir, http_services)
        ssl_scanner.perform_scan()
        ssl_scanner.parse_results()
        ssl_scanner.print_results()

def check_tool_availability(class_name, requirements, project_dir):
    output.print_title(f"Checking {class_name} : Requirements")

    # Directory
    # Create root directory and subdirectories
    dir_path = os.path.join(project_dir, "Scans", class_name)
    try:
        os.makedirs(dir_path, exist_ok=True)
        output.print_info("Creating Directory", dir_path)
    except OSError as error:
        output.print_error(f"Error creating directory {dir_path}: {error}")
        return None


    # Tools
    missing_tools = []

    # Check tools in PATH
    for tool in requirements:
        if shutil.which(tool) is None:
            missing_tools.append(tool)
        else:
            output.print_info(tool, "Found")

    if missing_tools:
        output.print_error("The following tools are missing and are required to run this script:", "")
        for tool in missing_tools:
            output.print_error(f"- {tool}")
        return False
    else:
        return True

def create_project_structure(project_code, client_name, scope):
    output.print_title("Creating File Structure")
    output.print_info(f"Project Code", project_code)
    output.print_info("Client Name:", client_name)
    
    
    # Root directory name
    project_dir = f"Projects/Project_{project_code}_{client_name}"

    # Subdirectories
    subdirs = [
        "Scans",
        "Notes"
    ]

    # Create root directory and subdirectories
    for subdir in subdirs:
        dir_path = os.path.join(project_dir, subdir)
        try:
            os.makedirs(dir_path, exist_ok=True)
            output.print_info("Creating Directory", dir_path)
        except OSError as error:
            output.print_error(f"Error creating directory {dir_path}: {error}")
            return None

    # Save the scope to a file in the project directory
    scope_file_path = os.path.join(project_dir, "scope.txt")
    with open(scope_file_path, 'w') as scope_file:
        if isinstance(scope, list):
            scope_file.write('\n'.join(scope))
        else:
            scope_file.write(scope)

    return project_dir


def get_scope(scope_input):
    # Check if the input is a file path
    if os.path.isfile(scope_input):
        # Read targets from the file
        with open(scope_input, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    else:
        # Split the string by commas and strip whitespace
        return [target.strip() for target in scope_input.split(',') if target.strip()]


def main():

    # Set up argument parser
    parser = argparse.ArgumentParser(description="Automated Scanning Tool")
    parser.add_argument("-p", "--project_code", required=True, help="The code of the project")
    parser.add_argument("-c", "--client_name", required=True, help="The name of the client")
    parser.add_argument("-s", "--scope", required=True, help="The target IP/URL or a file containing a list of targets")
    args = parser.parse_args()

    # # Load configuration
    # config = load_config('config.json')

    # Process the scope
    scope = get_scope(args.scope)

    # Create project structure and save the scope
    project_dir = create_project_structure(args.project_code, args.client_name, scope)

    # Execute Scans
    output.print_title("Scanning Phase Started")
    execute_scans(scope, project_dir)
    output.print_title("Scanning Phase Completed")


if __name__ == "__main__":

    output.print_banner()
    output.print_title("Making Initial Recon: Keen Assessment Tool")
    main()
