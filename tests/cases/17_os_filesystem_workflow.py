import glob
import os
import shutil
import tempfile
from pathlib import Path


start = os.getcwd()
root = tempfile.mkdtemp(prefix="pyguard_fs_")

try:
    base = Path(root)
    nested = base / "alpha" / "beta"
    nested.mkdir(parents=True)
    os.chdir(nested)

    Path("data.txt").write_text("line1\nline2\n", encoding="utf-8")
    with open("data.bin", "wb") as fh:
        fh.write(bytes(range(16)))

    os.makedirs("../gamma", exist_ok=True)
    os.replace("data.txt", "../gamma/moved.txt")
    shutil.copyfile("data.bin", "../gamma/copy.bin")

    text = Path("../gamma/moved.txt").read_text(encoding="utf-8").splitlines()
    blob = Path("../gamma/copy.bin").read_bytes()
    rel = os.path.relpath(base / "alpha" / "gamma" / "moved.txt", base)
    matches = sorted(Path(p).name for p in glob.glob("../gamma/*"))

    print(os.path.basename(root).startswith("pyguard_fs_"))
    print("|".join(text))
    print(sum(blob), len(blob), rel.replace(os.sep, "/"))
    print(",".join(matches))
finally:
    os.chdir(start)
    shutil.rmtree(root, ignore_errors=True)
