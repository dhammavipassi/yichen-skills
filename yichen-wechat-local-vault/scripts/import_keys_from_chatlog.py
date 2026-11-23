#!/usr/bin/env python3
"""从本机 chatlog 容器恢复 WeChat 4.x SQLCipher key。

对每个源库读取前 16 字节 salt，使用 `/app/data/chatlog.json` 中的 `data_key`
执行 PBKDF2-HMAC-SHA512（256000 轮）派生并通过 `try_decrypt_page` 校验。
默认脱敏账号标识，不输出任何密钥明文。

用法：
  python3 scripts/import_keys_from_chatlog.py
  python3 scripts/import_keys_from_chatlog.py --container chatlog-v4-b
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from decrypt_all_dbs import ALIAS_TO_REL, KEYS_FILE, load_json, resolve_db_base, save_json  # noqa: E402
from extract_keys import try_decrypt_page  # noqa: E402

PBKDF2_ROUNDS = 256000
PBKDF2_ALGO = "sha512"
SHARD_RE = re.compile(r"^message_(\d+)\.db$")


def _mask_wxid(wxid: str, show_sensitive: bool = False) -> str:
    if show_sensitive or not wxid:
        return wxid or "<unknown>"
    if len(wxid) <= 6:
        return "***"
    return f"{wxid[:3]}***{wxid[-3:]}"


def _running_containers() -> list[str]:
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"docker unavailable: {exc}")
    return [line.strip() for line in out.stdout.splitlines() if line.strip()]


def _chatlog_config(container: str) -> dict | None:
    try:
        out = subprocess.run(
            ["docker", "exec", container, "cat", "/app/data/chatlog.json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=15,
        )
        return json.loads(out.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def _find_container(wxid: str, *, show_sensitive: bool = False) -> str:
    matches = []
    for name in _running_containers():
        cfg = _chatlog_config(name)
        if cfg and str(cfg.get("account") or "") == wxid:
            matches.append(name)
    masked = _mask_wxid(wxid, show_sensitive)
    if not matches:
        raise SystemExit(f"no running chatlog container exposes account {masked}")
    if len(matches) > 1:
        raise SystemExit(
            f"multiple chatlog containers expose {masked}: {', '.join(matches)}; pass --container"
        )
    return matches[0]


def _target_aliases(db_base: Path) -> dict[str, str]:
    targets = dict(ALIAS_TO_REL)
    msg_dir = db_base / "message"
    if msg_dir.is_dir():
        for item in sorted(msg_dir.iterdir()):
            m = SHARD_RE.match(item.name)
            if m and item.is_file():
                targets.setdefault(f"message_{m.group(1)}", f"message/{item.name}")
    return targets


def main() -> int:
    parser = argparse.ArgumentParser(description="Recover vault keys from a local chatlog container")
    parser.add_argument("--container", default="", help="chatlog container name; default auto-detect by vault wxid")
    parser.add_argument("--db-base", default="", help="source db_storage path; default from vault config")
    parser.add_argument("--key-file", default=str(KEYS_FILE))
    parser.add_argument("--show-sensitive", action="store_true", help="include unredacted account id in output")
    args = parser.parse_args()

    db_base = Path(args.db_base).expanduser() if args.db_base else resolve_db_base()
    if args.container:
        cfg = _chatlog_config(args.container)
        if not cfg:
            raise SystemExit(f"cannot read chatlog config from explicit container: {args.container}")
    else:
        args.container = _find_container(db_base.parent.name, show_sensitive=args.show_sensitive)
        cfg = _chatlog_config(args.container)
        if not cfg:
            raise SystemExit(f"cannot read chatlog config from {args.container}")

    wxid = str(cfg.get("account") or "")
    passphrase_hex = str(cfg.get("data_key") or "")
    try:
        passphrase = bytes.fromhex(passphrase_hex)
    except ValueError:
        raise SystemExit("chatlog data_key is not hex; cannot derive")
    if len(passphrase) != 32:
        raise SystemExit(f"chatlog data_key is {len(passphrase)} bytes, expected 32")

    keys = load_json(Path(args.key_file).expanduser())
    derived = 0
    for alias, rel in _target_aliases(db_base).items():
        src = db_base / rel
        if not src.is_file():
            continue
        with src.open("rb") as handle:
            salt = handle.read(16)
        if len(salt) != 16:
            continue
        dk = hashlib.pbkdf2_hmac(PBKDF2_ALGO, passphrase, salt, PBKDF2_ROUNDS, 32).hex()
        if try_decrypt_page(str(src), dk):
            keys[alias] = dk
            derived += 1
    if not derived:
        raise SystemExit("none of the source databases decrypt with this chatlog key")
    key_path = Path(args.key_file).expanduser()
    save_json(key_path, keys)
    print(
        f"recovered {derived} key(s) for {_mask_wxid(wxid, args.show_sensitive)} from {args.container}"
    )
    print(f"written: {key_path} (mode 600)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
