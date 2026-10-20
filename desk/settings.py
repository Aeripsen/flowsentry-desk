"""Paths, pins and knobs for FlowSentry Desk.

Everything a number depends on is pinned here: the FlowSentry commit, the hashes of the
upstream files the build downloads, the reject threshold that defines the queue, and the
cap the close gate is tuned to. Runtime knobs (API key, Clerk, model id) come from the
environment and are read by the modules that need them.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# FlowSentry is imported as a dependency at this exact commit (pyproject.toml pins the
# same tarball). The desk never edits FlowSentry; it only calls its loader, split and model.
FLOWSENTRY_COMMIT = "1299cd8c3ed19f0677d170b8973e64589d070430"
FLOWSENTRY_RAW = f"https://raw.githubusercontent.com/Aeripsen/flowsentry/{FLOWSENTRY_COMMIT}/"

# sha256 of each file as committed upstream (the git blob, LF line endings).
UPSTREAM_FILES = {
    "data/sample/bccc_udp_quic_sample.csv.gz":
        "3707e5f5e9bee8efb0a6ee8be6e285343d38a4b24c28cf7bc308276b428f9f3b",
    "artifacts/metrics.json":
        "9be6090dbbef357b1455bcdcfcde576ad60c1d8f0a0d1993e8ca0cf0fefea9ac",
    "artifacts/business_case.json":
        "48727fa5d171d6a81a8df5ab789b9866f6fae240eef515e93cd4220eb7c02985",
}

BUILD_DIR = ROOT / "build"                 # gitignored: downloads, the retrained model
UPSTREAM_DIR = BUILD_DIR / "upstream"
FS_ARTIFACT_DIR = BUILD_DIR / "fs_artifacts"

DATA_DIR = ROOT / "data"
BUNDLE_PATH = DATA_DIR / "desk_bundle.npz"  # committed: everything the app reads at runtime
MANIFEST_PATH = DATA_DIR / "desk_manifest.json"
RUNS_DIR = ROOT / "runs"                    # committed: cached agent runs for the demo queue
REPORTS_DIR = ROOT / "reports"              # committed: the measured evaluation
WEB_DIR = ROOT / "web"

# The queue: FlowSentry's held-out flows whose confidence is below this threshold.
# 0.99 is FlowSentry's headline threshold (2,315 of 6,570 held-out flows).
REJECT_THRESHOLD = 0.99

# The close knob. For each cap, the gate threshold is the loosest one whose 95% Wilson upper
# bound on attacks wrongly closed, per 1,000 closed, is at most the cap on TRAINING data
# (out of fold). The default is the strictest cap the training data can certify. History
# (build log): 10 was fixed first and could not be met; 20 neither; the knob replaced the
# single cap before the test queue was scored.
GATE_CAPS_PER_1000 = (10.0, 20.0, 30.0, 50.0, 100.0)

# Precedents: how many labelled neighbours each case gets.
K_NEIGHBOURS = 15

# The six rare UDP DDoS families FlowSentry reports on (all except benign and UDP-RAW).
RARE_FAMILIES = ["UDP-GAME", "UDP-HULK", "UDP-MULTI", "UDP-OVH", "UDP-VSE", "UDP-bypass-v1"]

# Agent limits.
MAX_TOOL_STEPS = 8


def env_flag(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def db_path() -> Path:
    return Path(os.environ.get("DESK_DB_PATH", str(ROOT / "desk.sqlite3")))
