import json
import re
import shlex
import subprocess
from typing import List

import requests

from .output_manager import OutputManager


def check_internet(url: str) -> bool:
    """Return True if the specified URL is reachable."""
    try:
        requests.get(url, timeout=5)
        return True
    except requests.RequestException:
        return False


def send_scan_results(scan_results: dict, llm_ip: str) -> str:
    """Send scan results to the Ollama server and return the response text."""
    url = f"http://{llm_ip}/api/generate"
    payload = {
        "model": "llama3",
        "prompt": "Analyze these scan results and suggest next commands to run:\n"
        + json.dumps(scan_results, indent=2),
        "stream": False,
    }
    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status()
    data = response.json()
    return data.get("response", "")


def extract_commands(text: str) -> List[str]:
    """Extract shell commands from the LLM response text."""
    commands: List[str] = []
    code_blocks = re.findall(r"```(?:bash|sh)?\n(.*?)```", text, re.DOTALL)
    for block in code_blocks:
        for line in block.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                commands.append(line)
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("$ "):
            commands.append(line[2:])
    return commands


def execute_commands(commands: List[str], output_manager: OutputManager) -> None:
    """Execute a list of commands securely without using the shell."""
    for cmd in commands:
        output_manager.print_info("Executing", cmd)
        try:
            result = subprocess.run(
                shlex.split(cmd), capture_output=True, text=True, check=True
            )
            if result.stdout:
                output_manager.print_info("Output", result.stdout.strip())
            if result.stderr:
                output_manager.print_warning(result.stderr.strip())
        except subprocess.CalledProcessError as e:
            output_manager.print_error(f"Command '{cmd}' failed: {e}")
