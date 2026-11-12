"""PreToolUse hook: catat setiap pemanggilan tool ke .claude/logs/pretooluse.log.

Hook ini hanya untuk audit. Ia tidak pernah memblokir tool: kegagalan apa pun
ditelan dan script selalu keluar dengan kode 0.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


def main() -> None:
    raw = sys.stdin.read()
    try:
        payload = json.dumps(json.loads(raw), ensure_ascii=False, separators=(",", ":"))
    except ValueError:
        payload = raw.strip()

    project_dir = Path(os.environ.get("CLAUDE_PROJECT_DIR") or Path(__file__).resolve().parents[2])
    log_file = project_dir / ".claude" / "logs" / "pretooluse.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with log_file.open("a", encoding="utf-8") as f:
        f.write(f"{stamp} {payload}\n\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass
    sys.exit(0)
