import os
import pandas as pd
from Core import config

class ReportGenerator:
    def __init__(self, all_results, project_path):
        self.all_results = all_results
        self.reports_dir = os.path.join(project_path, config.REPORTS_DIR_NAME)
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)

    def _collect_rows(self):
        rows = []
        for ip, ports in self.all_results.items():
            for port, details in ports.items():
                for detail in details.values():
                    if not isinstance(detail, dict):
                        continue

                    vulnerabilities = detail.get('Details', {}).get('vulnerabilities')
                    if vulnerabilities:
                        for vuln in vulnerabilities:
                            rows.append([
                                ip,
                                port,
                                vuln.get('Vulnerability'),
                                vuln.get('Severity'),
                                vuln.get('Description'),
                            ])
                    else:
                        rows.append([
                            ip,
                            port,
                            detail.get('Vulnerability'),
                            detail.get('Severity'),
                            detail.get('Description'),
                        ])
        return rows

    def generate_excel_report(self):
        rows = self._collect_rows()
        df = pd.DataFrame(rows, columns=['IP', 'Port', 'Vulnerability', 'Severity', 'Description'])
        excel_file = os.path.join(self.reports_dir, config.EXCEL_REPORT_FILENAME)
        df.to_excel(excel_file, index=False)
        print(f"Excel report generated at {excel_file}")

    def generate_html_report(self):
        rows = self._collect_rows()
        df = pd.DataFrame(rows, columns=['IP', 'Port', 'Vulnerability', 'Severity', 'Description'])
        html_file = os.path.join(self.reports_dir, config.HTML_REPORT_FILENAME)
        df.to_html(html_file, index=False)
        print(f"HTML report generated at {html_file}")
