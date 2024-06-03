import pandas as pd
import json

def extract_vulnerabilities_from_excel(excel_file, json_output_file):
    # Read the Excel file
    xls = pd.ExcelFile(excel_file)

    # Initialize an empty list to store the vulnerabilities
    vulnerabilities = []

    # Iterate through each sheet in the Excel file
    for sheet_name in xls.sheet_names:
        df = pd.read_excel(xls, sheet_name=sheet_name)
        # Iterate through each row in the sheet
        for _, row in df.iterrows():
            # Extract relevant fields, replacing NaN with empty strings
            vulnerability = {
                "Reference": row.get("Reference", ""),
                "Type": row.get("Type", ""),
                "Title": row.get("Title", ""),
                "Impact": row.get("Impact", ""),
                "Severity": row.get("Severity", ""),
                "Likelihood": row.get("Likelihood", ""),
                "FixEffort": row.get("Fix Effort", ""),
                "CVSSScore": row.get("CVSS Score", ""),
                "Description": row.get("Description", ""),
                "AffectedComponents": row.get("Affected Components", ""),
                "Recommendation": row.get("Recommendation", ""),
                "Status": row.get("Status", ""),
                "IssueOwner": row.get("Issue Owner", ""),
                "Notes": row.get("Notes", ""),
                "Completed": row.get("Completed", ""),
                "CompletedDate": row.get("Completed Date", "")
            }

            # Convert NaN values to empty strings
            vulnerability = {k: ("" if pd.isna(v) else v) for k, v in vulnerability.items()}

            # Remove findings which are all blank
            if any(vulnerability.values()):
                vulnerabilities.append(vulnerability)

    # Write the vulnerabilities to a JSON file
    with open(json_output_file, 'w') as json_file:
        json.dump(vulnerabilities, json_file, indent=4)

# Example usage
excel_file = 'Findings.xlsx'
json_output_file = 'vulnerability_dataset.json'
extract_vulnerabilities_from_excel(excel_file, json_output_file)
