import os
import argparse
from colorama import Fore, Style
import json
import shutil
import importlib.util
import subprocess
import re
from plugin_interface import ScannerPlugin



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

        acronym = "M.I.R.K.A.T"
        acronym_ex = "Monitoring Intelligence & Reconnaissance: Knowledge Acquisition Tool"

        centered_ascii = (Fore.YELLOW + f"{ascii_art}" + Style.RESET_ALL).center(self.title_width)
        centered_acronym = (Fore.YELLOW + f"{acronym}" + Style.RESET_ALL).center(self.title_width)
        centered_acronym_ex = (Fore.YELLOW + f"{acronym_ex}" + Style.RESET_ALL).center(self.title_width)

        print(f"{centered_ascii}\n{centered_acronym}\n{centered_acronym_ex}")          

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


class PluginManager:
    def __init__(self, plugin_directory, project_dir, scope, results):
        self.plugins = []
        self.plugin_directory = plugin_directory
        self.project_dir = project_dir
        self.targets = scope

        self.results = results
        print(self.results)
        self.load_plugins()

    def load_plugins(self):
            output.print_title("Detecting Plugins")
            for file in os.listdir(self.plugin_directory):
                if file.startswith('plugin_') and file.endswith('.py'):
                    file_path = os.path.join(self.plugin_directory, file)
                    module_name = file[:-3]  # Remove .py
                    output.print_info("Plugin Detected",module_name)
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    for attribute_name in dir(module):
                      attribute = getattr(module, attribute_name)
                      if isinstance(attribute, type) and issubclass(attribute, ScannerPlugin) and attribute is not ScannerPlugin:
                        # loaded_plugin = attribute(self.project_dir, self.targets) # Double prints "Checking Nmap"
                        # print(f"Loaded plugin type: {type(loaded_plugin)}")  # Debugging print
                        self.plugins.append(attribute(self.project_dir, self.targets, self.results))

    def run_scans(self):
        for plugin in self.plugins:
            self.results = plugin.run_scan(self.results)
            # plugin.parse_results()
        # self.parse_results()

    def parse_results(self):
        output.print_title("Parsing Results")
        for host in self.results:
            print(f"Results for {host}: {self.results[host]}")
        pass

class Mirkat ():
    def __init__(self):
        # Load configuration
        self.project_dir = ""


    def create_project_structure(self, project_dir, scope):
        output.print_title("Creating File Structure")
        
        self.project_dir = project_dir
        print(project_dir)
        # Root directory name
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

        return None


    
    def check_tool_availability(self, class_name, requirements, output_dir):
        output.print_title(f"Checking Requirements for: {class_name}")

        # Create root directory and subdirectories
        try:
            os.makedirs(output_dir, exist_ok=True)
            output.print_info("Creating Directory", output_dir)
        except OSError as error:
            output.print_error(f"Error creating directory {output_dir}: {error}")
            return None
        except Exception as error:
            output.print_error(f"Error creating directory {output_dir}: {error}")
            return None


        # Tools
        missing_tools = []

        # Check tools in PATH
        for tool in requirements:
            if shutil.which(tool) is None:
                missing_tools.append(tool)
            else:
                output.print_info(tool, "Found in system path")

        if missing_tools:
            output.print_error("The following tools are missing and are required to run this script:", "")
            for tool in missing_tools:
                output.print_error(f"- {tool}")
            return False
        else:
            return True

# Tools

class EyeWitnessScans():
    def __init__(self, project_dir, http_services):
        ## CHANGE THIS ##
        self.class_name = "eyewitness"
        # Do not change
        self.output = OutputManager()
        self.config = config.read_config()
        self.http_services = http_services
        self.root_dir = project_dir
        self.results = {}
        self.ports = []
        self.http_services = []  # Initialize as a dictionary
        self.output_dir = os.path.join(self.root_dir, f"Scans/{self.class_name}")
       
        # Create Directory

        # Additonal Settings
        tools_required = ["nmap"]
        # check_tool_availability(self.class_name, tools_required, self.output_dir)    

    def run_scan(self):
        self._create_output_directory()
        urls_file_path = self._write_http_services_to_file()
        self._execute_eyewitness_scan(urls_file_path)

    def _create_output_directory(self):
        # Ensure the EyeWitness output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

    def _write_http_services_to_file(self):
        # Write the HTTP/HTTPS services to a file
        urls_file_path = os.path.join(self.root_dir, "http_services.txt")
        with open(urls_file_path, 'w') as file:
            for url in self.http_services:
                file.write(url + "\n")
        return urls_file_path

    def _execute_eyewitness_scan(self, urls_file_path):
        # Construct and run the EyeWitness command
        eyewitness_command = f"eyewitness --web -f {urls_file_path} --no-prompt -d {self.output_dir}"
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
        ## CHANGE THIS ##
        self.class_name = "SSLScan"
        # Do not change
        self.output = OutputManager()
        self.config = config.read_config()
        self.targets = targets
        self.root_dir = project_dir
        self.results = {}
        self.ports = []
        self.http_services = []  # Initialize as a dictionary
        self.output_dir = os.path.join(self.root_dir, f"Scans/{self.class_name}")

        # Additonal Settings
        tools_required = ["sslscan"]
        # check_tool_availability(self.class_name, tools_required, self.output_dir)


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

    # Process the scope
    scope = get_scope(args.scope)


    project_dir = f"Projects/Project_{args.project_code}_{args.client_name}"
    

    plugin_manager = PluginManager("plugins", project_dir, scope, "")


    # Execute Scans
    output.print_title("Scanning Phase Started")
    # execute_scans(scope, project_dir)
    plugin_manager.run_scans()
    output.print_title("Scanning Phase Completed")


if __name__ == "__main__":
    output.print_banner()
 
    main()
