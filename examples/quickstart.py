import os
import secrets
import tempfile
from pathlib import Path

from audit_chain import ChainAnchor, append_entry, parse_jsonl, to_jsonl_line, verify_jsonl

key = secrets.token_bytes(32)  # a random HMAC key; in production, load it from your secret manager
keyring = {"k1": key}
path = Path(tempfile.mkdtemp()) / "audit.jsonl"


def append(record: dict) -> dict:
    data = path.read_bytes() if path.exists() else b""
    result = verify_jsonl(data, keyring)  # never seal onto a chain that does not verify
    if not result.ok:
        raise RuntimeError(f"refusing to append: {result.error}")
    entries = parse_jsonl(data).entries
    entry = append_entry(entries[-1] if entries else None, record, key, writer_key_id="k1")
    with path.open("ab") as f:  # bytes: a text-mode writer could change the line endings
        f.write(to_jsonl_line(entry))
        f.flush()
        os.fsync(f.fileno())  # on disk before the head is stored anywhere
    return entry


append({"event": "user.login", "user": "alice"})
last = append({"event": "payment.refund", "user": "alice", "amount_pence": 1900})
head = ChainAnchor(last["seq"] + 1, last["entry_hash"])

# Later, an auditor: every entry verifies, and the file ends exactly at the stored head.
print(verify_jsonl(path.read_bytes(), keyring, head))

# Change one name in the history: verification now fails at that entry.
path.write_bytes(path.read_bytes().replace(b"alice", b"mallory", 1))
print(verify_jsonl(path.read_bytes(), keyring, head))
