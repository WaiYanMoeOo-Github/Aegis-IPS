import os
import sys
import glob
import time
import shutil
import subprocess
import platform
from typing import Optional


def find_standard_windows_python() -> Optional[str]:
    """Locate a standard win_amd64 Python interpreter (not MSYS2/MinGW)."""
    candidates = []
    local_pattern = os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python3*\python.exe")
    prog_pattern = r"C:\Program Files\Python3*\python.exe"
    candidates.extend(sorted(glob.glob(local_pattern), reverse=True))
    candidates.extend(sorted(glob.glob(prog_pattern), reverse=True))

    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def ensure_standard_python_on_windows():
    """If invoked via MSYS2/MinGW Python on Windows, switch to standard Windows Python."""
    if platform.system() != "Windows":
        return

    is_msys = (
        "MSYS" in sys.version
        or "MINGW" in sys.version
        or "msys64" in sys.executable.lower()
    )
    if not is_msys:
        return

    print("[INFO] MSYS2/MinGW Python detected. Switching to standard Windows Python...")
    std_python = find_standard_windows_python()
    if std_python:
        print(f"[INFO] Using: {std_python}\n")
        subprocess.check_call([std_python, os.path.abspath(__file__)])
        sys.exit(0)
    else:
        print("[ERROR] Please install standard Windows Python from https://www.python.org/downloads/ and re-run.")
        sys.exit(1)


def find_ollama_binary(os_name: str) -> Optional[str]:
    """Locate the ollama executable even if PATH hasn't refreshed after install."""
    path_bin = shutil.which("ollama")
    if path_bin:
        return path_bin

    if os_name == "Windows":
        win_default = os.path.expandvars(r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe")
        if os.path.exists(win_default):
            return win_default
    elif os_name in ("Linux", "Darwin"):
        for candidate in (
            "/usr/local/bin/ollama",
            "/opt/homebrew/bin/ollama",
            "/Applications/Ollama.app/Contents/Resources/ollama",
        ):
            if os.path.exists(candidate):
                return candidate
    return None


def setup_venv(os_name: str) -> str:
    """Create a native virtual environment and install Python dependencies."""
    venv_dir = "venv"
    if not os.path.exists(venv_dir):
        print("[1/4] Creating virtual environment (venv)...")
        subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
    else:
        print("[1/4] Existing 'venv' directory found.")

    venv_python = (
        os.path.join(venv_dir, "Scripts", "python.exe")
        if os_name == "Windows"
        else os.path.join(venv_dir, "bin", "python")
    )

    print("[2/4] Installing Python dependencies from requirements.txt...")
    subprocess.check_call([venv_python, "-m", "pip", "install", "--upgrade", "pip"])
    subprocess.check_call([venv_python, "-m", "pip", "install", "-r", "requirements.txt"])
    return venv_python


def install_ollama(os_name: str) -> Optional[str]:
    """Check if Ollama is installed; run official install script if missing."""
    print("[3/4] Checking Ollama installation...")
    ollama_bin = find_ollama_binary(os_name)
    if ollama_bin:
        print(f"      Ollama found at: {ollama_bin}")
        return ollama_bin

    print("      Ollama not found. Running official installer script...")
    try:
        if os_name == "Windows":
            ps_bin = shutil.which("powershell") or shutil.which("pwsh")
            if not ps_bin:
                print("      [WARNING] PowerShell not found. Download Ollama manually from https://ollama.com/download")
                return None
            subprocess.check_call([
                ps_bin,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "irm https://ollama.com/install.ps1 | iex",
            ])

        elif os_name in ("Linux", "Darwin"):
            subprocess.check_call(["sh", "-c", "curl -fsSL https://ollama.com/install.sh | sh"])

        return find_ollama_binary(os_name)
    except Exception as e:
        print(f"      [WARNING] Automatic Ollama install failed: {e}")
        print("      Please download and install Ollama manually from https://ollama.com/download")
        return None


def ensure_llm_model(ollama_bin: Optional[str], model_name: str = "llama3.2"):
    """Ensure the Ollama service is running and pull the required LLM model."""
    if not ollama_bin:
        print(f"[4/4] Skipping '{model_name}' model pull (Ollama not installed).")
        return

    print(f"[4/4] Checking local LLM model ({model_name})...")
    check = subprocess.run([ollama_bin, "list"], capture_output=True, text=True)
    if check.returncode != 0:
        print("      Starting Ollama background service...")
        subprocess.Popen(
            [ollama_bin, "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(3)
        check = subprocess.run([ollama_bin, "list"], capture_output=True, text=True)

    if check.returncode == 0 and model_name in check.stdout:
        print(f"      Model '{model_name}' is already available.")
        return

    print(f"      Pulling '{model_name}' model (this may take a few minutes)...")
    try:
        subprocess.check_call([ollama_bin, "pull", model_name])
        print(f"      Model '{model_name}' ready.")
    except Exception as e:
        print(f"      [WARNING] Failed to pull '{model_name}': {e}")
        print(f"      Run 'ollama pull {model_name}' manually after setup.")


def check_os_network_prereqs(os_name: str):
    """Verify OS-level packet sniffing and firewall dependencies."""
    print("\n[NETWORK CHECK] Verifying OS-level dependencies...")
    if os_name == "Windows":
        npcap_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap")
        if os.path.exists(npcap_dir):
            print("      Npcap driver detected.")
        else:
            print("      [ACTION REQUIRED] Npcap is NOT installed!")
            print("      Download and install Npcap from https://npcap.com/ (enable 'WinPcap API-compatible Mode').")

    elif os_name == "Linux":
        if not shutil.which("iptables") and shutil.which("apt-get"):
            print("      Installing iptables via apt...")
            subprocess.call(["sudo", "apt-get", "update"])
            subprocess.call(["sudo", "apt-get", "install", "-y", "iptables"])
        else:
            print("      Linux network tools (iptables) ready.")


def main():
    ensure_standard_python_on_windows()
    os_name = platform.system()
    print(f"=== Aegis-AI IPS Cross-Platform Setup ({os_name}) ===\n")

    venv_python = setup_venv(os_name)
    ollama_bin = install_ollama(os_name)
    ensure_llm_model(ollama_bin, "llama3.2")
    check_os_network_prereqs(os_name)

    print("\n=== Setup Complete ===")
    print("Run Aegis-AI IPS with Administrator / root privileges:")
    if os_name == "Windows":
        print(f"  1. {venv_python} -m uvicorn main:app --host 0.0.0.0 --port 8000")
        print(f"  2. {venv_python} sensor.py")
    else:
        print(f"  1. sudo {venv_python} -m uvicorn main:app --host 0.0.0.0 --port 8000")
        print(f"  2. sudo {venv_python} sensor.py")


if __name__ == "__main__":
    main()