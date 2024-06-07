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
        self.output_manager = output_manager
        self.output_dir = os.path.join(self.project_path, "Scans", "SSLScan")
        self.vuln_manager = VulnManager()

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def run(self):
        http_ports = {"80", "443", "8080", "8443"}

        for ip, ports in self.nmap_results.items():
            for port, details in ports.items():
                if port in http_ports:
                    self.output_manager.print_info("Running SSL scan on", f"{ip}:{port}")
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
                    self._display_scan_results(ip, port, scan_results)
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

    def _highlight_vulnerabilities(self, scan_results):
        vulnerabilities_found = False
        for vulnerability in scan_results['vulnerabilities']:
            vulnerabilities_found = True
            self.output_manager.print_warning(f"  {vulnerability['Vulnerability']}: {vulnerability['Description']}")
        
        if not vulnerabilities_found:
            self.output_manager.print_info("  No critical vulnerabilities identified.", "")

    def _display_scan_results(self, ip, port, scan_results):
        self.output_manager.print_divider()
        self.output_manager.print_info(f"SSL Scan Results for {ip}:{port}", "")
        
        if scan_results['protocols']:
            self.output_manager.print_info("Enabled Protocols:", "")
            for protocol in scan_results['protocols']:
                self.output_manager.print_info(f"  {protocol['type'].upper()} {protocol['version']}", "")
        
        if scan_results['ciphers']:
            self.output_manager.print_info("Accepted Ciphers:", "")
            for cipher in scan_results['ciphers']:
                self.output_manager.print_info(f"  {cipher['sslversion']} {cipher['cipher']} ({cipher['strength']})", "")
        
        if scan_results['certificates']:
            self.output_manager.print_info("Certificates:", "")
            for cert in scan_results['certificates']:
                self.output_manager.print_info(f"  Subject: {cert.get('subject', 'unknown')}", "")
                self.output_manager.print_info(f"  Issuer: {cert.get('issuer', 'unknown')}", "")
                self.output_manager.print_info(f"  Signature Algorithm: {cert.get('signature_algorithm', 'unknown')}", "")
                self.output_manager.print_info(f"  Public Key Type: {cert.get('pk_type', 'unknown')} ({cert.get('pk_bits', 'unknown')} bits)", "")
                self.output_manager.print_info(f"  Self-Signed: {cert.get('self_signed', 'unknown')}", "")
                self.output_manager.print_info(f"  Expired: {cert.get('expired', 'unknown')}", "")
                self.output_manager.print_info(f"  Valid From: {cert.get('not-valid-before', 'unknown')}", "")
                self.output_manager.print_info(f"  Valid To: {cert.get('not-valid-after', 'unknown')}", "")
        
        self.output_manager.print_divider()
        self.output_manager.print_info("Identified Vulnerabilities:", "")
        self._highlight_vulnerabilities(scan_results)
        self.output_manager.print_divider()
