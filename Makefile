# Every target is one command, so Windows users without make can run the line directly.
PY ?= python

.PHONY: help install install-build data verify-data eval test lint serve dev record-agent eval-agent docker docker-run hf-space

help:
	@echo "install       runtime + test dependencies"
	@echo "serve         run the desk on http://localhost:8000 (no key needed)"
	@echo "test          run the tests"
	@echo "data          rebuild data/desk_bundle.npz from FlowSentry (downloads ~9 MB, ~1 min)"
	@echo "verify-data   rebuild and compare with the committed bundle"
	@echo "eval          the oracle-analyst evaluation -> reports/eval.json"
	@echo "record-agent  record Claude runs for the demo queue -> runs/recorded.jsonl (needs ANTHROPIC_API_KEY)"
	@echo "eval-agent    evaluate recorded model runs -> reports/agent_eval.json"
	@echo "docker        build the image; docker-run serves it on :7860"

install:
	$(PY) -m pip install -r requirements.txt

install-build:
	$(PY) -m pip install -r requirements-build.txt

data:
	$(PY) -m desk.build

verify-data:
	$(PY) scripts/verify_bundle.py

eval:
	$(PY) -m desk.evaluate

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check desk tests scripts

serve:
	$(PY) -m uvicorn desk.app:app --port 8000

dev:
	$(PY) -m uvicorn desk.app:app --port 8000 --reload

record-agent:
	$(PY) scripts/record_agent.py --n 40

eval-agent:
	$(PY) scripts/eval_agent.py

docker:
	docker build -t flowsentry-desk .

docker-run:
	docker run --rm -p 7860:7860 flowsentry-desk

hf-space:
	$(PY) scripts/make_hf_space.py
