import os
import subprocess
import sys

import shutil

def build():
    print("Building TypePaste...")
    
    # Clean previous builds
    if os.path.exists("dist"):
        shutil.rmtree("dist")
    if os.path.exists("build"):
        shutil.rmtree("build")
    if os.path.exists("TypePaste.spec"):
        os.remove("TypePaste.spec")

    # Run PyInstaller
    # --onefile: Create a single executable
    # --windowed: No console window
    # --name TypePaste: Name of the executable
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", "TypePaste",
        "typepaste_gui.py"
    ]
    
    print(f"Running: {' '.join(cmd)}")
    subprocess.check_call(cmd)
    
    print("Build complete!")
    
    exe_name = "TypePaste.exe" if os.name == 'nt' else "TypePaste"
    if os.path.exists(os.path.join("dist", exe_name)):
         print(f"Artifact in 'dist/': {exe_name}")
    else:
         print("Error: Output executable not found.")

if __name__ == "__main__":
    build()
