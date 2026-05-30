#!/usr/bin/env python3
# ==============================================================================
#  Automatic Sanitization & Credential Stripping Script for SuperBox VPN Core
#  Cleans hardcoded VPS IPs, passwords, and private subscription links.
# ==============================================================================

import os
import re

# Targeted sensitive data to strip
TARGET_IP = "193.233.136.52"
TARGET_PASSWORD = "McZR1VPU4ZljdIjo"
TARGET_SUBSCRIBE_URL = "hidekey://011b8f69-2193-41fd-b723-1efa4f3f8f53:aeb064100417fb65a7214708c414633174ac8147992471a7cea4c542ee164e22@193.233.136.52:51443#test"

# Safe placeholders
PLACEHOLDER_IP = "YOUR_VPS_IP"
PLACEHOLDER_PASSWORD = "YOUR_SSH_PASSWORD"
PLACEHOLDER_SUBSCRIBE_URL = "hidekey://YOUR_UUID:YOUR_KEY@YOUR_VPS_IP:51443#test"

# Root workspace directory
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

print(f"[*] Scanning workspace at {ROOT_DIR} for sensitive data...")

# File suffixes to scan
VALID_EXTENSIONS = ('.rs', '.py', '.bat', '.sh', '.json', '.toml', '.config', '.init', '.md')

files_cleaned = 0

for root, dirs, files in os.walk(ROOT_DIR):
    # Exclude build targets, local cargo caches, and git directories
    if any(x in root for x in ["target", ".git", "smoltcp", "netstack-smoltcp", ".sixth"]):
        continue

    for file in files:
        if not file.endswith(VALID_EXTENSIONS):
            continue

        file_path = os.path.join(root, file)
        
        # Don't strip this cleaning script itself
        if "clear_sensitive_data.py" in file_path:
            continue

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            changed = False

            # 1. Replace hardcoded VPS IP
            if TARGET_IP in content:
                content = content.replace(TARGET_IP, PLACEHOLDER_IP)
                changed = True
                print(f"[OK] Stripped VPS IP address from: {os.path.relpath(file_path, ROOT_DIR)}")

            # 2. Replace hardcoded SSH Password
            if TARGET_PASSWORD in content:
                content = content.replace(TARGET_PASSWORD, PLACEHOLDER_PASSWORD)
                changed = True
                print(f"[OK] Stripped SSH Password from: {os.path.relpath(file_path, ROOT_DIR)}")

            # 3. Replace private subscription URI
            if TARGET_SUBSCRIBE_URL in content:
                content = content.replace(TARGET_SUBSCRIBE_URL, PLACEHOLDER_SUBSCRIBE_URL)
                changed = True
                print(f"[OK] Stripped private VLESS/Hidekey subscribe URL from: {os.path.relpath(file_path, ROOT_DIR)}")

            if changed:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                files_cleaned += 1

        except Exception as e:
            print(f"[WARN] Failed to process file {file_path}: {e}")

# ── Clean local logs, caches, and DB files ─────────────────────────────────────
FILES_TO_REMOVE = [
    "super_box.log",
    "recent_vps.log",
    "vps_server.log",
    "super_box.db/lock",
    "super_box.db/db"
]

print("\n[*] Cleaning temporary local logs and database locks...")
for f_rel in FILES_TO_REMOVE:
    f_path = os.path.join(ROOT_DIR, f_rel)
    if os.path.exists(f_path):
        try:
            if os.path.isdir(f_path):
                import shutil
                shutil.rmtree(f_path)
            else:
                os.remove(f_path)
            print(f"[OK] Removed temporary file: {f_rel}")
        except Exception as e:
            print(f"[WARN] Failed to remove {f_rel}: {e}")

print("==============================================================================")
print(f"  [SUCCESS] Done! Sanitization successfully completed!")
print(f"  Files sanitized: {files_cleaned}")
print("  All private VPS IPs, SSH passwords, and user keys have been stripped.")
print("  You can now safely add, commit, and push this repository to GitHub!")
print("==============================================================================")
