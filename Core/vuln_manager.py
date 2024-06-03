import json
from Core.config import VULNERABILITY_DETAILS_FILE, VULNERABILITY_DATASET_FILE

class VulnManager:
    def __init__(self, details_file=VULNERABILITY_DETAILS_FILE, dataset_file=VULNERABILITY_DATASET_FILE):
        self.details_file = details_file
        self.dataset_file = dataset_file
        self.vulnerabilities = self.load_vulnerability_details()
        self.dataset = self.load_vulnerability_dataset()

    def load_vulnerability_details(self):
        try:
            with open(self.details_file, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            print(f"Warning: Vulnerability details file {self.details_file} not found. Starting with an empty dataset.")
            return {}
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from the vulnerability details file: {e}")
            return {}

    def load_vulnerability_dataset(self):
        try:
            with open(self.dataset_file, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            print(f"Warning: Vulnerability dataset file {self.dataset_file} not found. Starting with an empty dataset.")
            return []
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON from the vulnerability dataset file: {e}")
            return []

    def update_vulnerability_details(self, new_details):
        self.vulnerabilities.update(new_details)
        with open(self.details_file, 'w') as file:
            json.dump(self.vulnerabilities, file, indent=4)
    
    def get_vulnerability_detail(self, vuln_id):
        return self.vulnerabilities.get(vuln_id)

    def add_vulnerability(self, vuln_id, detail):
        if vuln_id not in self.vulnerabilities:
            self.vulnerabilities[vuln_id] = detail
            self.update_vulnerability_details({vuln_id: detail})
        else:
            print(f"Vulnerability {vuln_id} already exists. Use update_vulnerability_details to modify it.")
    
    def search_vulnerability_by_title_or_description(self, text):
        matches = []
        for vuln in self.dataset:
            if text.lower() in vuln['Title'].lower() or text.lower() in vuln['Description'].lower():
                matches.append(vuln)
        return matches

# Example usage
if __name__ == "__main__":
    vuln_manager = VulnManager()
    new_vuln_detail = {
        "CVSSv3": "8.8",
        "Description": "Example vulnerability description.",
        "Remediation": "Example remediation steps."
    }
    vuln_manager.add_vulnerability("CVE-2021-XXXX", new_vuln_detail)
    print(vuln_manager.get_vulnerability_detail("CVE-2021-XXXX"))

    # Searching for vulnerabilities
    search_results = vuln_manager.search_vulnerability_by_title_or_description("tls 1.0")
    for result in search_results:
        print(result)
