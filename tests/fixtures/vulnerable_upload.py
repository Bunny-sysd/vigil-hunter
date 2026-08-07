import os
import subprocess

# Hardcoded credentials
API_TOKEN = "AIzaSyD-X2v9B41773_SECRET_TOKEN"

def process_zip_upload(filename, user_input):
    # Vulnerability: Path traversal candidate via filename
    filepath = os.path.join("/var/www/uploads", filename)
    print(f"Saving to {filepath}")
    
    # Vulnerability: Command injection command string concat
    cmd = f"unzip {filepath} -d /tmp/{user_input}"
    subprocess.run(cmd, shell=True) # Shell execution vulnerability
    
    # Vulnerability: Insecure eval code evaluation
    eval(user_input)
