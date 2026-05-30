import json
import os

def main():
    # b420fb19-3356-4511-957f-f8b75fdb4208 is the stealth_coder conversation ID
    log_path = r"C:\Users\User\.gemini\antigravity\brain\b420fb19-3356-4511-957f-f8b75fdb4208\.system_generated\logs\transcript.jsonl"
    if not os.path.exists(log_path):
        print(f"[-] Subagent log path does not exist: {log_path}")
        return

    print(f"[*] Reading subagent transcript.jsonl from {log_path}...")
    
    count = 0
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "tls_tunnel.rs" in line and ("write_to_file" in line or "replace_file_content" in line):
                count += 1
                try:
                    obj = json.loads(line)
                    print(f"Match {count}: Index={obj.get('step_index')}, Type={obj.get('type')}")
                    if "tool_calls" in obj:
                        for call in obj["tool_calls"]:
                            name = call.get("name", "")
                            if "write_to_file" in name or "replace_file_content" in name:
                                args = call.get("args", {})
                                content = args.get("CodeContent", "") or args.get("ReplacementContent", "")
                                print(f"  Found code content! Length: {len(content)}")
                                # Save to a scratch file
                                out_name = f"C:\\Users\\User\\Desktop\\super box\\scratch\\subagent_tls_tunnel_{obj.get('step_index')}.rs"
                                with open(out_name, "w", encoding="utf-8") as out_f:
                                    out_f.write(content)
                                print(f"  Saved to {out_name}")
                except Exception as e:
                    print(f"  Error parsing: {e}")

if __name__ == "__main__":
    main()
