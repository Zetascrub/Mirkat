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
        self.class_name = "Eyewitness"
        self.tools_required = ["eyewitness"]
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


        for host in self.results:
            print(self.results[host])
            for port in self.results[host]:
                if self.results[host][port]["Service"] is "http" or "https":
                    print(f"HTTP service found on {host}:{port}")

        pass

    def run_scan(self, results):
        # Construct and run the EyeWitness command
        eyewitness_command = f"eyewitness --web -f {urls_file_path} --no-prompt -d {self.output_dir}"
        output.log_message(f"Command Ran: {eyewitness_command}")

        return self.results

    def parse_results(self, output_file, target):
        pass