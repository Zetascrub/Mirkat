import os
import subprocess
import xml.etree.ElementTree as ET
from Core.plugin_base import PluginBase
from Core.vuln_manager import VulnManager
from Core.output_manager import OutputManager

class SslScanner(PluginBase):
    def __init__(self, nmap_results, output_manager, project_path):
        super().__init__(nmap_results, output_manager)
        self.project_path = project_path
        self.output_manager = OutputManager()
        self.output_dir = os.path.join(self.project_path, "SSLScan")
        self.vuln_manager = VulnManager()

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def run(self):
        http_ports = {"80", "443", "8080", "8443"}

        for ip, ports in self.nmap_results.items():
            for port, details in ports.items():
                if port in http_ports:
                    self.output_manager.print_info(f"Running SSL scan on",f"{ip}:{port}")
                    scan_target = f"{ip}:{port}"
                    output_file_path = os.path.join(self.output_dir, f"{scan_target.replace(':', '-')}_sslscan.xml")
                    self._run_sslscan(scan_target, output_file_path)
                    scan_results = self._parse_results(output_file_path)
                    details['sslscan'] = {
                        'Vulnerability': 'SSL/TLS Configuration',
                        'Severity': 'Info',
                        'Description': 'SSL scan results',
                        'Details': scan_results
                    }
                    # Search for related vulnerabilities
                    vulnerabilities = self.identify_vulnerabilities(scan_results)
                    if vulnerabilities:
                        for vuln in vulnerabilities:
                            details[f'sslscan_{vuln["Title"]}'] = vuln

    def _run_sslscan(self, target, output_file):
        ssl_scan_command = f"sslscan --xml={output_file} {target}"
        try:
            subprocess.run(ssl_scan_command, check=True, shell=True, stdout=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            self.output_manager.print_error(f"Error during SSL scan on {target}: {e}")

    def _parse_results(self, output_file):
        ssl_scan_results = {
            'protocols': [],
            'certificates': [],
            'ciphers': [],
            'vulnerabilities': []
        }

        tree = ET.parse(output_file)
        root = tree.getroot()

        for protocol in root.findall('.//protocol'):
            if protocol.get('enabled') == '1':
                protocol_info = {
                    'type': protocol.get('type'),
                    'version': protocol.get('version'),
                }
                ssl_scan_results['protocols'].append(protocol_info)
                # Check for insecure protocols
                if protocol_info['version'] in ['1.0', '1.1']:
                    vulnerability = {
                        'Vulnerability': f"Insecure {protocol_info['type'].upper()} {protocol_info['version']}",
                        'Severity': 'High',
                        'Description': f"{protocol_info['type'].upper()} {protocol_info['version']} is considered insecure and should not be used."
                    }
                    ssl_scan_results['vulnerabilities'].append(vulnerability)

        for cipher in root.findall('.//cipher[@status="accepted"]'):
            ssl_scan_results['ciphers'].append({
                'sslversion': cipher.get('sslversion'),
                'cipher': cipher.get('cipher'),
                'strength': cipher.get('strength'),
            })

        for certificate in root.findall('.//certificate'):
            ssl_scan_results['certificates'].append({
                'signature_algorithm': certificate.find('signature-algorithm').text if certificate.find('signature-algorithm') is not None else 'unknown',
                'pk_type': certificate.find('pk').get('type') if certificate.find('pk') is not None else 'unknown',
                'pk_bits': certificate.find('pk').get('bits') if certificate.find('pk') is not None else 'unknown',
                'self_signed': certificate.find('self-signed').text if certificate.find('self-signed') is not None else 'unknown',
                'expired': certificate.find('expired').text if certificate.find('expired') is not None else 'unknown',
            })

        return ssl_scan_results

    def identify_vulnerabilities(self, scan_results):
        vulnerabilities = []
        for protocol in scan_results['protocols']:
            if protocol['version'] in ['1.0', '1.1']:
                matches = self.vuln_manager.search_vulnerability_by_title_or_description(f"{protocol['type'].upper()} {protocol['version']}")
                vulnerabilities.extend(matches)
        return vulnerabilities
