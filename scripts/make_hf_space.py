"""Assemble the Hugging Face Space folder (Docker SDK, free CPU, no card).

    python scripts/make_hf_space.py --out build/hf_space

The Space is the same Docker image as everywhere else. The only difference is the README:
Spaces read their settings from YAML front matter, which would render as a table on GitHub,
so the Space gets its own README with the front matter on top.
"""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FRONT = """---
title: FlowSentry Desk
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: Triage agent for flows FlowSentry won't call
---

"""

COPY = ["Dockerfile", "requirements.txt", "LICENSE", "desk", "web", "data", "runs", "reports"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "build" / "hf_space"))
    out = Path(ap.parse_args().out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name in COPY:
        src = ROOT / name
        if src.is_dir():
            shutil.copytree(src, out / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        else:
            shutil.copy2(src, out / name)
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    (out / "README.md").write_text(FRONT + readme, encoding="utf-8", newline="\n")
    (out / ".gitattributes").write_text("*.npz binary\n", encoding="utf-8")
    print(f"Space folder ready: {out}")


if __name__ == "__main__":
    main()
