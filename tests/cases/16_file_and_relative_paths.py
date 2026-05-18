import os
from pathlib import Path


here = Path(__file__).resolve().parent
target = here / "_pyguard_relative_probe.txt"

try:
    target.write_text("relative-ok", encoding="utf-8")
    rel = os.path.relpath(target, os.getcwd())
    print(Path(__file__).name)
    print(open(rel, encoding="utf-8").read())
finally:
    try:
        target.unlink()
    except FileNotFoundError:
        pass
