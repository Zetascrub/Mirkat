import argparse
import os
import importlib
from Core.vuln_manager import VulnManager
from Core.report_generator import ReportGenerator
from Core.output_manager import OutputManager
from Core.utils import setup_logging, read_scope_from_file, is_valid_ip
from Core.nmap_scanner import NmapScanner
from Core.plugin_base import PluginBase
from Core import config

class Mirkat:
    def __init__(self, project_code, client_name, scope, llm_ip=None):
        self.project_code = project_code
        self.client_name = client_name
        self.scope = self.parse_scope(scope)
        self.llm_ip = llm_ip
        self.output_manager = OutputManager()
        self.vuln_manager = VulnManager()
        self.scan_results = {}
        self.project_path = None

    def parse_scope(self, scope):
        if os.path.isfile(scope):
            return read_scope_from_file(scope)
        return [ip.strip() for ip in scope.split(',') if is_valid_ip(ip.strip())]

    def setup_project_directory(self, project_dir):
        self.project_path = config.get_full_path(os.path.join(project_dir, f"Project_{self.project_code}_{self.client_name.replace(' ', '_')}"))
        os.makedirs(self.project_path, exist_ok=True)
        os.makedirs(os.path.join(self.project_path, config.SCAN_RESULTS_DIR_NAME), exist_ok=True)
        os.makedirs(os.path.join(self.project_path, config.REPORTS_DIR_NAME), exist_ok=True)
        self.output_manager.print_divider()
        self.output_manager.print_info("Project directory setup at", self.project_path)
        # self.output_manager.print_divider()

    def execute_scans(self):
        nmap_scanner = NmapScanner(self.scope, self.scan_results, self.output_manager, self.project_path)
        self.scan_results = nmap_scanner.perform_scan()

        self.run_plugins()

        all_results = self.scan_results

        for ip, ports in all_results.items():
            for port, details in ports.items():
                # Filter only valid detail dictionaries
                valid_details = [detail for detail in details.values() if isinstance(detail, dict) and 'vuln_id' in detail]
                for detail in valid_details:
                    self.vuln_manager.add_vulnerability(detail['vuln_id'], detail)

        return all_results

    def run_plugins(self):
        plugins_dir = os.path.join(os.path.dirname(__file__), 'Scanners')
        for plugin_file in os.listdir(plugins_dir):
            if plugin_file.endswith('.py') and plugin_file != '__init__.py':
                module_name = f'Scanners.{plugin_file[:-3]}'
                module = importlib.import_module(module_name)
                for attribute_name in dir(module):
                    attribute = getattr(module, attribute_name)
                    if isinstance(attribute, type) and issubclass(attribute, PluginBase) and attribute is not PluginBase:
                        self.output_manager.print_info("Running plugin", f"{module_name}.{attribute_name}")
                        plugin_instance = attribute(self.scan_results, self.output_manager, self.project_path)
                        plugin_instance.run()

    def generate_reports(self, all_results):
        report_gen = ReportGenerator(all_results, self.project_path)
        report_gen.generate_excel_report()
        report_gen.generate_html_report()

    def generate_executive_summary(self, llm_ip):
        pass

def parse_arguments():
    parser = argparse.ArgumentParser(description="Automated Scanning Tool")
    parser.add_argument("-p", "--project_code", required=True, help="The code of the project")
    parser.add_argument("-c", "--client_name", required=True, help="The name of the client")
    parser.add_argument("-s", "--scope", required=True, help="The target IP/URL or a file containing a list of targets")
    parser.add_argument("-l", "--llm", required=False, help="The IP of the Ollama API")
    return parser.parse_args()

def main():
    args = parse_arguments()
    setup_logging(log_file_name=f"{args.project_code}_{args.client_name}.log")
    mirkat = Mirkat(project_code=args.project_code, client_name=args.client_name, scope=args.scope, llm_ip=args.llm)
    mirkat.setup_project_directory(config.PROJECT_DIR)
    all_results = mirkat.execute_scans()
    mirkat.generate_reports(all_results)
    if args.llm:
        mirkat.generate_executive_summary(args.llm)

if __name__ == "__main__":
    main()
