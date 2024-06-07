import subprocess
import os
from xml.etree import ElementTree as ET
from Core.output_manager import OutputManager
from Core import config

class NmapScanner:
    def __init__(self, scope, scan_results, output_manager, project_path):
        self.module_name = "Nmap"
        self.scope = scope
        self.scan_results = scan_results
        self.output_manager = output_manager
        self.output_dir = os.path.join(project_path, config.SCAN_RESULTS_DIR_NAME, self.module_name)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def perform_scan(self):
        self.output_manager.print_divider()
        for target in self.scope:
            output_file = os.path.join(self.output_dir, f"{target}_nmap.xml").replace(" ", "_")
            command = f"nmap -oX {output_file} {target}"
            self.output_manager.print_info("Running command", command)
            try:
                result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                self.output_manager.log_message(f"Nmap output: {result.stdout}")
                self.output_manager.log_message(f"Nmap errors: {result.stderr}")
                self.output_manager.print_info("Checking for output file", output_file)
                if os.path.exists(output_file):
                    self.parse_results(output_file, target)
                else:
                    self.output_manager.print_error(f"Nmap did not create the expected output file: {output_file}")
            except subprocess.CalledProcessError as e:
                self.output_manager.print_error(f"Error running Nmap scan on {target}: {e}")
        self.output_manager.print_divider()
        self.output_manager.print_info("Scan results", "")
        self.display_scan_results()
        self.output_manager.print_divider()
        return self.scan_results

    def parse_results(self, output_file, target):
        try:
            tree = ET.parse(output_file)
            root = tree.getroot()
            target_results = {}

            for host in root.findall('host'):
                ip_address = host.find('address').get('addr')
                for port in host.findall('ports/port'):
                    port_id = port.get('portid')
                    service = port.find('service').get('name')
                    state = port.find('state').get('state')
                    if ip_address not in self.scan_results:
                        self.scan_results[ip_address] = {}
                    self.scan_results[ip_address][port_id] = {
                        'Service': service,
                        'State': state,
                        'Vulnerability': 'Nmap Scan',
                        'Severity': 'Info',
                        'Description': f'{service} service detected on port {port_id} ({state})'
                    }
        except FileNotFoundError:
            self.output_manager.print_error(f"File not found during parsing: {output_file}")
        except ET.ParseError as e:
            self.output_manager.print_error(f"Error parsing XML file {output_file}: {e}")

    def display_scan_results(self):
        for ip, ports in self.scan_results.items():
            self.output_manager.print_info(f"Host: {ip}", "Open ports:")
            for port_id, details in ports.items():
                service = details['Service']
                state = details['State']
                self.output_manager.print_info(f"  - Port {port_id}/{state}", f"Service: {service}")
