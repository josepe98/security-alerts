#!/Users/erikjosephson/.venv/bin/python
"""Regression test: nested lock files must be attributed to their own directory,
not the project root (SCA sub-project misattribution bug, found 2026-07-25).

Reproduces the canopy/frontend layout: root package-lock.json WITHOUT axios,
frontend/package-lock.json WITH vulnerable axios. Asserts the scan, exposure
hits, triage file, and LLM prompt all point at the frontend install dir —
previously they all said "canopy", so the generated remediation command
(`cd ~/canopy && npm install axios@...`) patched the wrong tree.

Run directly: ~/.venv/bin/python test_install_location.py
Needs no real credentials — env vars are stubbed before import.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("FASTMAIL_USER", "dummy@example.com")
os.environ.setdefault("FASTMAIL_APP_PASSWORD", "dummy")
os.environ.setdefault("ANTHROPIC_API_KEY", "dummy")

sys.path.insert(0, str(Path(__file__).parent))
import security_monitor as sm

failures = []


def check(desc, cond):
    print(("PASS" if cond else "FAIL") + f": {desc}")
    if not cond:
        failures.append(desc)


with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)

    # ── Fixture: canopy-like project ──────────────────────────────────────────
    canopy = tmp / "canopy"
    (canopy / "frontend").mkdir(parents=True)
    (canopy / "backend").mkdir()

    # Root lock file: no axios (matches real canopy pre-cleanup)
    (canopy / "package-lock.json").write_text(json.dumps({
        "name": "canopy", "lockfileVersion": 3,
        "packages": {"node_modules/left-pad": {"version": "1.3.0"}},
    }))
    # Nested frontend lock file: vulnerable axios
    (canopy / "frontend" / "package-lock.json").write_text(json.dumps({
        "name": "frontend", "lockfileVersion": 3,
        "packages": {"node_modules/axios": {"version": "1.16.0"}},
    }))
    # Nested backend requirements.txt (python path of the same bug)
    (canopy / "backend" / "requirements.txt").write_text("flask==2.0.0\n")

    stack_file = tmp / "stack.yaml"
    stack_file.write_text(f"project_paths:\n  - {canopy}\n")
    sm.STACK_FILE = stack_file

    # ── 1. build_installed_versions ───────────────────────────────────────────
    installed = sm.build_installed_versions()

    axios = installed["npm"].get("axios", [])
    check("axios found exactly once", len(axios) == 1)
    ver, label, path = axios[0]
    check(f"axios label is 'canopy/frontend' (got {label!r})", label == "canopy/frontend")
    check(f"axios install dir is frontend (got {path!r})", path == str(canopy / "frontend"))

    leftpad = installed["npm"].get("left-pad", [])
    check("root package label stays 'canopy'", bool(leftpad) and leftpad[0][1] == "canopy")
    check("root package path is project root", bool(leftpad) and leftpad[0][2] == str(canopy))

    flask = installed["pypi"].get("flask", [])
    check("nested requirements.txt label is 'canopy/backend'",
          bool(flask) and flask[0][1] == "canopy/backend")

    # ── 2. check_exposure ─────────────────────────────────────────────────────
    adv = sm.Advisory(
        id="ghsa:GHSA-test", source="GitHub Advisory",
        title="Axios test advisory", description="test", severity="MEDIUM",
        url="https://example.com", published="2026-07-25",
        packages=["axios"],
        affected_ranges=[{"ecosystem": "npm", "name": "axios",
                          "specifier": ">= 0.0.0, < 1.18.0", "fixed": "1.18.0"}],
    )
    hits = sm.check_exposure(adv, installed)
    check("one exposure hit", len(hits) == 1)
    h = hits[0]
    check("hit is exposed", h["exposed"] is True)
    check(f"hit project label is 'canopy/frontend' (got {h['project']!r})",
          h["project"] == "canopy/frontend")
    check(f"hit path is frontend dir (got {h.get('path')!r})",
          h.get("path") == str(canopy / "frontend"))

    # ── 3. write_triage_file ──────────────────────────────────────────────────
    triage_dir = tmp / "triage"
    sm.TRIAGE_DIR = triage_dir
    fname = sm.write_triage_file(
        adv, hits,
        {"impact_summary": "x", "proposed_action": "y",
         "upgrade_commands": [f"cd {canopy / 'frontend'} && npm install axios@^1.18.0"],
         "confidence": "HIGH"},
        "MEDIUM", "test reason")
    content = (triage_dir / fname).read_text()
    check("triage Exposure names canopy/frontend", "**canopy/frontend**" in content)
    check("triage Exposure includes the frontend install dir",
          f"`{canopy / 'frontend'}`" in content)
    check("triage does NOT attribute axios to bare project root",
          "in **canopy** " not in content)

    # ── 4. LLM prompt: Installed locations block ──────────────────────────────
    captured = {}

    class _FakeMsg:
        class _C:
            text = json.dumps({"impact_summary": "x", "proposed_action": "y",
                               "check_commands": [], "upgrade_commands": [],
                               "confidence": "HIGH"})
        content = [_C()]

    class _FakeMessages:
        def create(self, **kw):
            captured["prompt"] = kw["messages"][0]["content"]
            return _FakeMsg()

    class _FakeAnthropic:
        messages = _FakeMessages()

    sm.anthropic = _FakeAnthropic()

    sm.generate_investigation(adv, hits, "test reason", "MEDIUM")
    prompt = captured["prompt"]
    check("prompt lists the frontend install dir",
          f"install dir: {canopy / 'frontend'}" in prompt)
    check("prompt does not point at the project root",
          f"root: {canopy})" not in prompt and f"install dir: {canopy})" not in prompt)
    check("prompt instructs targeting install dirs", "install dirs" in prompt)

print()
if failures:
    print(f"{len(failures)} FAILURE(S)")
    sys.exit(1)
print("ALL CHECKS PASSED")
