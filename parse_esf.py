import json, csv
from datetime import datetime, timezone


def extract_paths(obj, found=None):
    if found is None: found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "path" and isinstance(v, str) and v:
                found.append(v)
            else:
                extract_paths(v, found)
    elif isinstance(obj, list):
        for item in obj: extract_paths(item, found)
    return found

def parse_esf_jsonl(input_path, output_path):
    rows = []

    with open(input_path, "rb") as f:
        raw = f.read()
    encoding = "utf-16" if raw[:2] in (b'\xff\xfe', b'\xfe\xff') else "utf-8"
    content = raw.decode(encoding)

    decoder = json.JSONDecoder()
    pos = 0
    content = content.lstrip('\ufeff')
    while pos < len(content):
        # Skip whitespace
        while pos < len(content) and content[pos] in ' \t\r\n':
            pos += 1
        if pos >= len(content):
            break
        try:
            event, pos = decoder.raw_decode(content, pos)
        except json.JSONDecodeError:
            # Skip a single bad character and retry, but if we're near EOF it's a truncated event
            remaining = content[pos:].lstrip()
            if remaining.startswith('{'):
                break  # truncated final event, stop here
            pos += 1
            continue

        proc = event.get("process", {})
        audit = proc.get("audit_token", {})
        evt_type = event.get("event_type")
        evt_data = event.get("event", {})
        action = event.get("action", {})
        result = action.get("result", {})
        result_inner = result.get("result", {})
        paths = extract_paths(evt_data)

        exec_data = evt_data.get("exec", {})
        args = exec_data.get("args", [])
        cmdline = " ".join(args) if args else ""

        raw_time = event.get("time", "")
        try:
            # ESF time is ISO 8601 with nanoseconds e.g. "2026-03-30T09:39:05.814694527Z"
            # Truncate fractional seconds to microseconds for Python compatibility
            ts = raw_time.rstrip("Z")
            if "." in ts:
                base, frac = ts.split(".", 1)
                ts = base + "." + frac[:6]
            dt_utc = datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
            date_time_utc = dt_utc.strftime("%Y-%m-%d %H:%M:%S.%f UTC")
            date_time_local = dt_utc.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f %Z")
        except (ValueError, TypeError):
            date_time_utc = ""
            date_time_local = ""

        rows.append({
            "date_time_local": date_time_local,
            "date_time_utc": date_time_utc,
            "mach_time": event.get("mach_time", ""),
            "global_seq_num": event.get("global_seq_num", ""),
            "seq_num": event.get("seq_num", ""),
            "event_type_id": evt_type,
            "action_type": event.get("action_type", ""),
            "result_type": result.get("result_type", ""),
            "result_auth": result_inner.get("auth", ""),
            "result_flags": result_inner.get("flags", ""),
            "process_pid": audit.get("pid", ""),
            "process_ppid": proc.get("ppid", ""),
            "process_uid": audit.get("ruid", ""),
            "process_gid": audit.get("rgid", ""),
            "process_euid": audit.get("euid", ""),
            "process_session_id": proc.get("session_id", ""),
            "process_exe": proc.get("executable", {}).get("path", ""),
            "process_signing_id": proc.get("signing_id", ""),
            "process_team_id": proc.get("team_id", ""),
            "process_is_platform_binary": proc.get("is_platform_binary", ""),
            "process_codesigning_flags": proc.get("codesigning_flags", ""),
            "process_start_time": proc.get("start_time", ""),
            "event_key": list(evt_data.keys())[0] if evt_data else "",
            "cmdline": cmdline,
            "paths": " | ".join(paths) if paths else "",
            "raw_event": json.dumps(evt_data),
        })

    if not rows:
        print("No events parsed.")
        return

    priority = ["date_time_local", "date_time_utc", "process_pid", "process_start_time", "process_exe", "event_key", "cmdline", "paths", "raw_event"]
    rest = [k for k in rows[0].keys() if k not in priority]
    fieldnames = priority + rest

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    max_len = max(len(r["raw_event"]) for r in rows)
    print(f"Done. {len(rows)} rows written to {output_path}")
    print(f"Longest raw_event field: {max_len} chars")


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3:
        parse_esf_jsonl(sys.argv[1], sys.argv[2])
    else:
        print("Usage: parse_esf.py <input.jsonl> <output.csv>")
        sys.exit(1)
