#!/usr/bin/env python3
import sys
from pathlib import Path

SELECTOR_COUNT = 256
FIRST_PORT = 60_000

if len(sys.argv) != 2:
    print("usage: generate-max-label-config.py OUTPUT", file=sys.stderr)
    raise SystemExit(2)

output = Path(sys.argv[1]).resolve()
text = "\n".join(
    "[[ports]]\n"
    'protocol = "tcp"\n'
    'address = "*"\n'
    f"port = {FIRST_PORT + index}\n"
    f'label = "service {index:03}"\n'
    for index in range(SELECTOR_COUNT)
)
with output.open("x", encoding="utf-8") as file:
    file.write(text)
print(f"wrote {SELECTOR_COUNT} selectors to {output}")
