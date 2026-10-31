"""
Seva Cyber Sandbox — Standalone Application Launcher
Phase 2: Complete Streamlit Removal

Provides a unified command-line interface to launch the Seva Cyber Sandbox:
1. Production Mode: Standalone FastAPI Server serving Liquid Glass 3D React UI on http://127.0.0.1:8000
2. Development Mode: Starts FastAPI API on port 8000 and Vite dev server on port 5173
"""

import argparse
import os
import subprocess
import sys
import webbrowser

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def run_production():
    """Run unified FastAPI server serving precompiled Liquid Glass frontend at http://127.0.0.1:8000"""
    print("=" * 70)
    print("  SEVA CYBER SANDBOX — STANDALONE FULL-STACK WEB APPLICATION")
    print("  React 19 + Three.js + FastAPI + Local/Supabase Persistence")
    print("=" * 70)
    print("Launching application on http://127.0.0.1:8000 ...")

    dist_index = os.path.join(BASE_DIR, "frontend", "dist", "index.html")
    if not os.path.isfile(dist_index):
        print("\nNotice: frontend/dist not found. Compiling React bundle with Vite...")
        npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
        subprocess.run([npm_cmd, "run", "build"], cwd=os.path.join(BASE_DIR, "frontend"), check=True)

    import uvicorn
    uvicorn.run("api_server:app", host="127.0.0.1", port=8000, reload=False)


def run_development():
    """Run Vite development server with hot-reloading alongside FastAPI backend."""
    print("Launching development environment...")
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    frontend_dir = os.path.join(BASE_DIR, "frontend")
    
    print("[*] Starting Vite dev server on http://localhost:5173 ...")
    subprocess.run([npm_cmd, "run", "dev"], cwd=frontend_dir)


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
