import argparse
import time
from datetime import datetime

from mirkat import Mirkat
from Core import config
from Core.llm_client import send_scan_results, extract_commands, execute_commands, check_internet
from Core.utils import setup_logging


def run_scan(project_code: str, client_name: str, scope: str, llm_ip: str | None):
    m = Mirkat(project_code=project_code, client_name=client_name, scope=scope, llm_ip=llm_ip)
    m.setup_project_directory(config.PROJECT_DIR)
    results = m.execute_scans()
    m.generate_reports(results)
    if llm_ip and check_internet(f"http://{llm_ip}"):
        try:
            response = send_scan_results(results, llm_ip)
            commands = extract_commands(response)
            if commands:
                execute_commands(commands, m.output_manager)
        except Exception as e:
            m.output_manager.print_error(f"LLM interaction failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="Continuous network monitoring")
    parser.add_argument("-s", "--scope", required=True, help="Targets to scan")
    parser.add_argument("-c", "--client_name", default="AutoClient", help="Client name")
    parser.add_argument("-p", "--project_prefix", default="AUTO", help="Project code prefix")
    parser.add_argument("-l", "--llm", required=False, help="Ollama server IP")
    parser.add_argument("-i", "--interval", type=int, default=3600, help="Seconds between scans")
    args = parser.parse_args()

    setup_logging("monitor.log")

    while True:
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        project_code = f"{args.project_prefix}_{timestamp}"
        run_scan(project_code, args.client_name, args.scope, args.llm)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
