"""
Seva Cyber Sandbox — Standalone Application Launcher
Phase 2: Complete Streamlit Removal

Provides a unified command-line interface to launch the Seva Cyber Sandbox:
1. Production Mode: Standalone FastAPI Server serving Liquid Glass 3D React UI on http://127.0.0.1:8000
2. Development Mode: Starts FastAPI API on port 8000 and Vite dev server on port 5173
"""

import argparse
import os
import socket
import subprocess
import sys
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def get_python_executable() -> str:
    """
    Locates the appropriate Python executable with uvicorn and required dependencies.
    Prioritizes project virtual environments (.venv, venv) before sys.executable.
    """
    candidates = []

    # 1. Virtual environments in project root
    if sys.platform == "win32":
        candidates.append(os.path.join(BASE_DIR, "venv", "Scripts", "python.exe"))
        candidates.append(os.path.join(BASE_DIR, ".venv", "Scripts", "python.exe"))
    else:
        candidates.append(os.path.join(BASE_DIR, "venv", "bin", "python"))
        candidates.append(os.path.join(BASE_DIR, ".venv", "bin", "python"))

    # 2. VIRTUAL_ENV environment variable
    if "VIRTUAL_ENV" in os.environ:
        if sys.platform == "win32":
            candidates.append(os.path.join(os.environ["VIRTUAL_ENV"], "Scripts", "python.exe"))
        else:
            candidates.append(os.path.join(os.environ["VIRTUAL_ENV"], "bin", "python"))

    # 3. Current sys.executable
    candidates.append(sys.executable)

    for py_candidate in candidates:
        if os.path.isfile(py_candidate):
            try:
                res = subprocess.run(
                    [py_candidate, "-c", "import uvicorn, fastapi; print('OK')"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode == 0 and "OK" in res.stdout:
                    return py_candidate
            except Exception:
                continue

    return sys.executable


def wait_for_backend(host: str = "127.0.0.1", port: int = 8000, timeout: float = 10.0) -> bool:
    """Polls TCP port until the FastAPI server begins accepting connections."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def run_production():
    """Run unified FastAPI server serving precompiled Liquid Glass frontend at http://127.0.0.1:8000"""
    print("=" * 70)
    print("  SEVA CYBER SANDBOX — STANDALONE FULL-STACK WEB APPLICATION")
    print("  React 19 + Three.js + FastAPI + Local/Supabase Persistence")
    print("=" * 70)

    dist_index = os.path.join(BASE_DIR, "frontend", "dist", "index.html")
    if not os.path.isfile(dist_index):
        print("\nNotice: frontend/dist not found. Compiling React bundle with Vite...")
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        subprocess.run([npm_cmd, "run", "build"], cwd=os.path.join(BASE_DIR, "frontend"), check=True)

    py_exe = get_python_executable()
    print(f"[*] Verified Python interpreter: {py_exe}")
    print("Launching application on http://127.0.0.1:8000 ...")

    if os.path.normcase(sys.executable) == os.path.normcase(py_exe):
        import uvicorn
        uvicorn.run("api_server:app", host="127.0.0.1", port=8000, reload=False)
    else:
        subprocess.run([py_exe, "-m", "uvicorn", "api_server:app", "--host", "127.0.0.1", "--port", "8000"])


def run_development():
    """Run Vite development server with hot-reloading alongside FastAPI backend."""
    print("=" * 70)
    print("  SEVA CYBER SANDBOX — DEVELOPMENT MODE")
    print("  FastAPI Backend (:8000) + Vite React Dev Server (:5173)")
    print("=" * 70)
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    frontend_dir = os.path.join(BASE_DIR, "frontend")
    py_exe = get_python_executable()

    print(f"[*] Verified Python interpreter: {py_exe}")
    print("[*] Starting FastAPI backend on http://127.0.0.1:8000 ...")
    backend_proc = subprocess.Popen(
        [py_exe, "-m", "uvicorn", "api_server:app", "--host", "127.0.0.1", "--port", "8000", "--reload"],
        cwd=BASE_DIR,
    )

    # Health check: Wait for port 8000 to be open or detect premature backend exit
    print("[*] Verifying backend availability before launching frontend...")
    for _ in range(10):
        if backend_proc.poll() is not None:
            print(f"\n[!] FATAL: FastAPI backend failed to start (Process exited with code {backend_proc.returncode}).")
            sys.exit(1)
        if wait_for_backend(host="127.0.0.1", port=8000, timeout=1.0):
            print("[+] FastAPI backend confirmed ONLINE on http://127.0.0.1:8000")
            break

    print("[*] Starting Vite dev server on http://localhost:5173 ...")
    try:
        subprocess.run([npm_cmd, "run", "dev"], cwd=frontend_dir)
    except KeyboardInterrupt:
        print("\n[*] Shutting down development servers...")
    finally:
        backend_proc.terminate()
        try:
            backend_proc.wait(timeout=5)
        except Exception:
            backend_proc.kill()


def main():
    parser = argparse.ArgumentParser(description="Seva Cyber Sandbox Launcher")
    parser.add_argument(
        "--mode",
        choices=["prod", "dev"],
        default="prod",
        help="Run mode: 'prod' for full-stack application (default: prod), 'dev' for Vite hot-reloading",
    )
    args = parser.parse_args()

    if args.mode == "dev":
        run_development()
    else:
        run_production()


if __name__ == "__main__":
    main()
