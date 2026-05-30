import json
import os

def main():
    log_path = r"C:\Users\User\.gemini\antigravity\brain\742170e3-95e5-43c9-a9c9-1daf724beda3\.system_generated\logs\transcript.jsonl"
    if not os.path.exists(log_path):
        print(f"[-] Log path does not exist: {log_path}")
        return

    print(f"[*] Reading transcript.jsonl from {log_path}...")
    
    count = 0
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "tls_tunnel.rs" in line:
                count += 1
                try:
                    obj = json.loads(line)
                    print(f"Match {count}: Index={obj.get('step_index')}, Type={obj.get('type')}, Status={obj.get('status')}")
                    # If model or tool call, print tool call name
                    if "tool_calls" in obj:
                        for call in obj["tool_calls"]:
                            print(f"  Tool Call: {call.get('name')}")
                            # Print a snippet of args
                            args_str = str(call.get("args", {}))
                            print(f"  Args snippet: {args_str[:150]}...")
                except Exception:
                    pass

if __name__ == "__main__":
    main()
