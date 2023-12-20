import subprocess
from plugin_interface import ScannerPlugin
import xml.etree.ElementTree as ET
from mirkat import output, config, Mirkat
import json
import os


class NmapPlugin(ScannerPlugin):
    def __init__(self, project_dir, scope, results):
        # Initialization code, like setting up default values or configurations
        ## CHANGE THIS ##
        self.class_name = "Nmap"
        self.tools_required = ["nmap"]
        ## DO NOT CHANGE THIS ##
        self.config = config.read_config()
        self.targets = scope
        self.project_dir = project_dir
        self.results = results
        self.ports = []
        self.http_services = []  # Initialize as a dictionary
        self.output_dir = f"{self.project_dir}/Scans/{self.class_name}"
        
        m = Mirkat()
        m.check_tool_availability(self.class_name, self.tools_required, self.output_dir)
        pass

    def run_scan(self, results):
        # Code to execute the Nmap scan
        for scan_type in self.config["nmap"]["scan_type"]:
            nmap_command_template = self.config["nmap"]["scan_type"][scan_type]
            for target in self.targets:
                output.print_info(f"Nmap {scan_type} Scan on {target}", "Started")
                nmap_output_file_path = os.path.join(self.output_dir, f"{target}_{scan_type}_scan.xml")
                if "tcp" in scan_type:
                    # Construct nmap command based on whether ports are specified
                    if len(self.ports) >= 1:
                        ports = set(self.ports)
                        # ports_str = ",".join(port.split('/')[0] for port in self.ports if '/' in port)
                        ports_str = ",".join(ports)               
                        output.print_info("Scanning specific ports:",f"{ports_str}")
                        nmap_command = f"{nmap_command_template} {nmap_output_file_path} -p {ports_str} {target} >> /dev/null"
                    else:
                        output.print_info("Scanning all ports","")
                        nmap_command = f"{nmap_command_template} {nmap_output_file_path} -p 0-65535 {target} >> /dev/null"
                # Parse the output file to update self.ports
                # self.parse_nmap_output(nmap_output_file_path)

                output.log_message(f"Command Ran: {nmap_command}")
                # self._execute_scan(nmap_command, nmap_output_file_path, target, scan_type)
                try:
                    with open(nmap_output_file_path, 'w') as output_file, open(os.devnull, 'w') as devnull:                        
                        subprocess.run(nmap_command, shell=True)
                except subprocess.SubprocessError as error:
                    output.print_error(f"Error during {scan_type} Nmap scan on {target}", error)
                output.print_info(f"Nmap {scan_type} Scan on {target}", "Completed")
                self.parse_results(nmap_output_file_path, target)
        # print(f"Results Overall: {json.dumps(self.results)}")
        return self.results

    def parse_results(self, output_file, target):
        tree = ET.parse(output_file)
        root = tree.getroot()

        # Initialize results dictionary
        results = {}

        # Example: Iterate through XML tree and extract data
        for host in root.findall('host'):
            ip_address = host.find('address').get('addr')
            results[ip_address] = {}

            for port in host.findall('.//port'):
                port_id = port.get('portid')
                self.ports.append(port_id)
                state = port.find('state').get('state')


                service_element = port.find('service')
                service_name = service_element.get('name', 'unknown') if service_element is not None else 'unknown'
                if "http" in service_name:
                    self.http_services.append(f"{ip_address}:{port_id}")

                service_element = port.find('service')
                service_product = service_element.get('product', 'unknown') if service_element is not None else 'unknown'

                service_element = port.find('service')
                service_version = service_element.get('version', 'unknown') if service_element is not None else 'unknown'
                
                

                results[ip_address][port_id] = {
                    'Service': service_name,
                    'Status': state,
                    'Product': service_product,
                    'Version': service_version
                }

        # Convert results to JSON (optional)
        # self.results[ip_address] = json_results
        results[host] = json.dumps(results, indent=4)
        self.results = results[host]
        print(f"Results for {ip_address}: {self.results}")
