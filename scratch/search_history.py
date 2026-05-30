import json
import os

def main():
    log_path = r"C:\Users\User\.gemini\antigravity\brain\742170e3-95e5-43c9-a9c9-1daf724beda3\.system_generated\logs\transcript.jsonl"
    if not os.path.exists(log_path):
        print(f"[-] Log path does not exist: {log_path}")
        return

    print(f"[*] Reading transcript.jsonl from {log_path}...")
    
    matches = []
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "build_chrome_client_hello" in line or "perform_chrome_tls_handshake" in line:
                try:
                    obj = json.loads(line)
                    matches.append(obj)
                except Exception:
                    pass

    print(f"[+] Found {len(matches)} matches!")
    
    # Save matches to a temporary file for analysis
    out_path = r"C:\Users\User\Desktop\super box\scratch\history_matches.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(matches, f, indent=2, ensure_ascii=False)
    print(f"[OK] Saved matches to {out_path}")

if __name__ == "__main__":
    main()
