"""
Vulnerable code sample for SourceAuditor testing.
"""

import hashlib
import os
import pickle
import sqlite3
import subprocess

API_KEY = "x89f2a9918bc741e9a302dfb8411c"


def execute_user_cmd(cmd: str):
    # CWE-78: Dangerous shell execution
    os.system(cmd)
    subprocess.run(f"echo {cmd}", shell=True)


def get_user_data(username: str):
    # CWE-89: SQL Injection
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchall()


def parse_payload(payload_bytes: bytes):
    # CWE-502: Insecure Deserialization
    return pickle.loads(payload_bytes)


def hash_password(password: str):
    # CWE-327: Weak Cryptographic Primitive
    return hashlib.md5(password.encode()).hexdigest()
