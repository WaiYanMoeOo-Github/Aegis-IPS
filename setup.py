import os
import sys
import time
import shutil
import subprocess
import platform


def find_ollama_binary(os_name: str) -> str | None:
    """Locate the ollama executable even if PATH hasn't refreshed after install."""
    path_bin = shutil.which("ollama")
    if path_bin:
        return path_bin

    if os_name == "Windows":
        win_default = os.path.expandvars(r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe")
        if os.path.exists(win_default):
            return win_default
    elif os_name in ("Linux", "Darwin"):
        for candidate in ("/usr/local/bin/ollama", "/opt/homebrew/bin/ollama"):
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


def install_ollama(os_name: str) -> str | None:
    """Check if Ollama is installed; attempt automatic installation if missing."""
    print("[3/4] Checking Ollama installation...")
    ollama_bin = find_ollama_binary(os_name)
    if ollama_bin:
        print(f"      Ollama found at: {ollama_bin}")
        return ollama_bin

    print("      Ollama not found. Attempting automatic installation...")
    try:
        if os_name == "Windows":
            if shutil.which("winget"):
                subprocess.check_call([
                    "winget", "install", "-e", "--id", "Ollama.Ollama",
                    "--accept-package-agreements", "--accept-source-agreements"
                ])
            else:
                print("      [WARNING] 'winget' not available. Download Ollama manually from https://ollama.com")
                return None

        elif os_name == "Linux":
            subprocess.check_call(["sh", "-c", "curl -fsSL https://ollama.com/install.sh | sh"])

        elif os_name == "Darwin":
            if shutil.which("brew"):
                subprocess.check_call(["brew", "install", "ollama"])
            else:
                print("      [WARNING] Homebrew not found. Download Ollama manually from https://ollama.com")
                return None

        return find_ollama_binary(os_name)
    except Exception as e:
        print(f"      [WARNING] Automatic Ollama install failed: {e}")
        print("      Please install Ollama manually from https://ollama.com")
        return None


def ensure_llm_model(ollama_bin: str | None, model_name: str = "llama3.2"):
    """Ensure the Ollama service is running and pull the required LLM model."""
    if not ollama_bin:
        print(f"[4/4] Skipping '{model_name}' model pull (Ollama not installed).")
        return

    print(f"[4/4] Checking local LLM model ({model_name})...")
    # Ensure Ollama server is reachable; start in background if needed
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