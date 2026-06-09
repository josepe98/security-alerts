#!/Users/erikjosephson/.venv/bin/python
"""
Security Alert Monitor v1
Sources : CISA Alerts RSS, GitHub Advisory Database, OSV, GitHub Security Blog, Bleeping Computer, Krebs on Security
Routing : HIGH/CRITICAL -> email  |  MEDIUM -> email
Delivery: Fastmail SMTP
Schedule: Every 60 minutes via launchd

Usage:
  python security_monitor.py            # normal run
  python security_monitor.py --test     # send a test email and exit
"""

import json
import logging
import os
import re
import smtplib
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import httpx
import yaml
from anthropic import Anthropic
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
STATE_FILE = BASE_DIR / "state.json"
STACK_FILE = BASE_DIR / "stack.yaml"
LOG_FILE   = BASE_DIR / "security_monitor.log"
TRIAGE_DIR  = BASE_DIR / "triage"
RECENT_JSON = TRIAGE_DIR / "recent.json"
RECENT_MD   = TRIAGE_DIR / "RECENT.md"
MAX_RECENT  = 10

# Maps our internal ecosystem keys → OSV ecosystem names (case-sensitive in OSV API)
INTERNAL_TO_OSV_ECO: dict[str, str] = {
    "npm":      "npm",
    "pypi":     "PyPI",
    "go":       "Go",
    "rubygems": "RubyGems",
    "composer": "Packagist",
}

# ── Logging ───────────────────────────────────────────────────────────────────
# Only add a stream handler when running interactively — launchd pipes stdout
# to the same log file as FileHandler, which would duplicate every line.
_log_handlers: list[logging.Handler] = [logging.FileHandler(LOG_FILE)]
if sys.stdout.isatty():
    _log_handlers.append(logging.StreamHandler(sys.stdout))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=_log_handlers,
)
log = logging.getLogger(__name__)

# ── Ecosystem helpers ─────────────────────────────────────────────────────────
def _normalize_eco(eco_raw: str) -> str:
    """Normalize ecosystem names from any source to our internal keys."""
    return {
        "npm":       "npm",
        "pip":       "pypi",
        "pypi":      "pypi",
        "go":        "go",
        "golang":    "go",
        "rubygems":  "rubygems",
        "ruby":      "rubygems",
        "packagist": "composer",
        "composer":  "composer",
        "php":       "composer",
    }.get(eco_raw.lower().strip(), eco_raw.lower().strip())


_MCP_CONFIG_FILENAMES: frozenset[str] = frozenset({
    "mcp.json", "claude_desktop_config.json", "mcp_config.json",
    "mcp_settings.json", "cline_mcp_settings.json", ".mcp.json",
})

# Path fragments that mark plugin marketplace caches and bundled template
# configs rather than servers the user actually connected. Without these,
# every server named in a never-installed plugin manifest (servicenow,
# zoominfo, benchling, ...) gets reported as part of the stack (see
# triage/bc_..._servicenow.md for the false positive this caused).
_MCP_IGNORED_PATH_PARTS: frozenset[str] = frozenset({
    "cowork_plugins", "local-agent-mode-sessions", "marketplaces",
    "cache", "configs", "node_modules",
})


def scan_mcp_configs() -> list[str]:
    """Scan known MCP config file locations and return a sorted list of server IDs.

    Looks in ~/.config, ~/Library/Application Support, and ~/.claude for any of
    the well-known MCP config filenames. Ported from Perplexity's bumblebee
    (internal/ecosystem/mcp/mcp.go). Skips plugin marketplace caches and
    template configs, which describe installable servers, not configured ones.
    """
    server_ids: set[str] = set()
    search_roots = [
        Path.home() / ".config",
        Path.home() / "Library" / "Application Support",
        Path.home() / ".claude",
    ]
    for root in search_roots:
        if not root.exists():
            continue
        for config_name in _MCP_CONFIG_FILENAMES:
            for config_file in root.rglob(config_name):
                if _MCP_IGNORED_PATH_PARTS.intersection(config_file.parts):
                    continue
                try:
                    data = json.loads(config_file.read_text())
                    servers = data.get("mcpServers", data.get("servers", {}))
                    if isinstance(servers, dict):
                        server_ids.update(servers.keys())
                except Exception:
                    pass
    return sorted(server_ids)


# ── Config from environment ───────────────────────────────────────────────────
def require_env(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        log.error(f"Missing required environment variable: {key}")
        sys.exit(1)
    return val

FASTMAIL_USER         = require_env("FASTMAIL_USER")
FASTMAIL_APP_PASSWORD = require_env("FASTMAIL_APP_PASSWORD")
ANTHROPIC_API_KEY     = require_env("ANTHROPIC_API_KEY")
GITHUB_TOKEN          = os.environ.get("GITHUB_TOKEN")  # Optional but recommended

anthropic = Anthropic(api_key=ANTHROPIC_API_KEY)

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


# ── State management ──────────────────────────────────────────────────────────
def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"seen_ids": [], "last_run": None}


def save_state(state: dict):
    state["seen_ids"] = list(set(state["seen_ids"]))[-20_000:]
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    STATE_FILE.write_text(json.dumps(state, indent=2))


# ── Stack context (for Claude relevance scoring) ──────────────────────────────
def build_stack_context(installed: dict | None = None) -> str:
    """Combine stack.yaml (platforms/runtimes) with live package scans.

    Args:
        installed: Output of build_installed_versions() — used to seed npm/pypi
                   package lists and add go/rubygems/composer sections so Haiku's
                   relevance scorer sees the full stack.
    """
    stack = yaml.safe_load(STACK_FILE.read_text())

    npm_packages:    set[str] = set(installed.get("npm",  {}).keys()) if installed else set()
    python_packages: set[str] = set(installed.get("pypi", {}).keys()) if installed else set()

    for raw_path in stack.get("project_paths", []):
        project = Path(raw_path).expanduser()
        if not project.exists():
            log.warning(f"Project path not found, skipping: {project}")
            continue

        for pkg_file in project.rglob("package.json"):
            if "node_modules" in pkg_file.parts or ".claude" in pkg_file.parts:
                continue
            try:
                data = json.loads(pkg_file.read_text())
                for section in ("dependencies", "devDependencies"):
                    npm_packages.update(data.get(section, {}).keys())
            except Exception as e:
                log.warning(f"Failed to parse {pkg_file}: {e}")

        for req_file in project.rglob("requirements.txt"):
            if ".claude" in req_file.parts:
                continue
            try:
                for line in req_file.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    pkg = line.split("==")[0].split(">=")[0].split("<=")[0] \
                               .split("~=")[0].split("[")[0].split(";")[0].strip()
                    if pkg:
                        python_packages.add(pkg.lower())
            except Exception as e:
                log.warning(f"Failed to parse {req_file}: {e}")

        for pyproject in project.rglob("pyproject.toml"):
            if ".claude" in pyproject.parts:
                continue
            try:
                data = tomllib.loads(pyproject.read_bytes().decode())
                deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                python_packages.update(k.lower() for k in deps if k.lower() != "python")
            except Exception as e:
                log.warning(f"Failed to parse {pyproject}: {e}")

    platforms = stack.get("platforms", [])
    runtimes  = stack.get("runtimes", [])

    lines = ["## Erik's Technology Stack\n"]
    lines.append("### Platforms & Cloud Services")
    for p in platforms:
        lines.append(f"- {p['name']} ({p.get('type', '')})")
    lines.append("\n### Runtimes")
    for r in runtimes:
        lines.append(f"- {r['name']} {r.get('version', '')}")
    lines.append(f"\n### npm Packages ({len(npm_packages)} packages)")
    lines.append(", ".join(sorted(npm_packages)))
    lines.append(f"\n### Python Packages ({len(python_packages)} packages)")
    lines.append(", ".join(sorted(python_packages)))

    # Additional ecosystems from bumblebee inventory
    if installed:
        for eco_key, eco_label in [
            ("go",       "Go Modules"),
            ("rubygems", "Ruby Gems"),
            ("composer", "Composer Packages"),
        ]:
            pkgs = sorted(installed.get(eco_key, {}).keys())
            if pkgs:
                lines.append(f"\n### {eco_label} ({len(pkgs)} packages)")
                lines.append(", ".join(pkgs))

    # MCP server IDs from Claude Desktop / Cursor / other MCP host configs
    mcp_servers = scan_mcp_configs()
    if mcp_servers:
        lines.append(f"\n### MCP Servers ({len(mcp_servers)} configured)")
        lines.extend(f"- {s}" for s in mcp_servers)

    return "\n".join(lines)


# ── Installed versions (for exposure checking) ────────────────────────────────
# Regex for Gemfile.lock spec lines — exactly 4-space indent, e.g. "    rails (7.1.0)"
_GEMFILE_SPEC_RE = re.compile(r'^    ([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)')


def build_installed_versions() -> dict[str, dict[str, list[tuple[str, str]]]]:
    """
    Scan lock files across all project_paths for every supported ecosystem.
    Returns: {"npm": {"axios": [("1.4.0", "canopy"), ...]},
              "pypi": ..., "go": ..., "rubygems": ..., "composer": ...}

    Ecosystem scanners ported from Perplexity's bumblebee open-source scanner:
      npm/pypi  — original logic
      go        — go.sum line parsing (bumblebee: internal/ecosystem/gomod/gomod.go)
      rubygems  — Gemfile.lock spec-block parsing (bumblebee: internal/ecosystem/rubygems)
      composer  — composer.lock JSON parsing (bumblebee: internal/ecosystem/composer)
    """
    result: dict[str, dict[str, list[tuple[str, str]]]] = {
        "npm": {}, "pypi": {}, "go": {}, "rubygems": {}, "composer": {},
    }
    stack_cfg = yaml.safe_load(STACK_FILE.read_text())

    for raw_path in stack_cfg.get("project_paths", []):
        project = Path(raw_path).expanduser()
        if not project.exists():
            continue
        project_name = project.name

        # ── npm: package-lock.json ─────────────────────────────────────────────
        for lock_file in project.rglob("package-lock.json"):
            if ".claude" in lock_file.parts or "node_modules" in lock_file.parts:
                continue
            try:
                data = json.loads(lock_file.read_text())
                lock_ver = data.get("lockfileVersion", 1)

                if lock_ver >= 2:
                    # v2/v3: packages dict keyed by "node_modules/<name>"
                    for key, val in data.get("packages", {}).items():
                        if not key.startswith("node_modules/"):
                            continue
                        # Strip "node_modules/" prefix; handle scoped packages
                        pkg_name = key.removeprefix("node_modules/").lower()
                        version  = val.get("version", "")
                        if pkg_name and version:
                            result["npm"].setdefault(pkg_name, []).append((version, project_name))
                else:
                    # v1: flat dependencies dict (may be nested)
                    def _collect_v1(deps: dict) -> None:
                        for pkg, info in deps.items():
                            version = info.get("version", "")
                            if version:
                                result["npm"].setdefault(pkg.lower(), []).append((version, project_name))
                            if "dependencies" in info:
                                _collect_v1(info["dependencies"])
                    _collect_v1(data.get("dependencies", {}))
            except Exception as e:
                log.warning(f"Failed to parse {lock_file}: {e}")

        # ── Python: requirements.txt (pinned lines only) ───────────────────────
        for req_file in project.rglob("requirements.txt"):
            if ".claude" in req_file.parts:
                continue
            try:
                for line in req_file.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "==" not in line:
                        continue
                    parts = line.split("==", 1)
                    pkg_name = parts[0].split("[")[0].strip().lower()
                    version  = parts[1].split(";")[0].strip()
                    if pkg_name and version:
                        result["pypi"].setdefault(pkg_name, []).append((version, project_name))
            except Exception as e:
                log.warning(f"Failed to parse {req_file}: {e}")

        # ── Python: poetry.lock ────────────────────────────────────────────────
        for poetry_lock in project.rglob("poetry.lock"):
            if ".claude" in poetry_lock.parts:
                continue
            try:
                content = poetry_lock.read_text()
                for block in re.split(r'\[\[package\]\]', content)[1:]:
                    name_m = re.search(r'name\s*=\s*"([^"]+)"', block)
                    ver_m  = re.search(r'version\s*=\s*"([^"]+)"', block)
                    if name_m and ver_m:
                        pkg_name = name_m.group(1).lower()
                        version  = ver_m.group(1)
                        result["pypi"].setdefault(pkg_name, []).append((version, project_name))
            except Exception as e:
                log.warning(f"Failed to parse {poetry_lock}: {e}")

        # ── Go: go.sum ────────────────────────────────────────────────────────────
        # Each line: "<module> <version> <hash>"  (two entries per module: source + go.mod)
        # Ported from bumblebee internal/ecosystem/gomod/gomod.go
        for go_sum in project.rglob("go.sum"):
            if ".claude" in go_sum.parts:
                continue
            try:
                for line in go_sum.read_text().splitlines():
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    module  = parts[0]
                    version = parts[1]
                    # Skip the "module v1.2.3/go.mod" pseudo-entries
                    if "/go.mod" in version:
                        continue
                    result["go"].setdefault(module, []).append((version, project_name))
            except Exception as e:
                log.warning(f"Failed to parse {go_sum}: {e}")

        # ── Ruby: Gemfile.lock ─────────────────────────────────────────────────
        # Ported from bumblebee internal/ecosystem/rubygems/rubygems.go
        for gemfile_lock in project.rglob("Gemfile.lock"):
            if ".claude" in gemfile_lock.parts:
                continue
            try:
                in_specs = False
                for line in gemfile_lock.read_text().splitlines():
                    if line.strip() == "specs:":
                        in_specs = True
                        continue
                    if in_specs:
                        if line and not line.startswith(" "):
                            in_specs = False
                            continue
                        m = _GEMFILE_SPEC_RE.match(line)
                        if m:
                            result["rubygems"].setdefault(m.group(1).lower(), []).append(
                                (m.group(2), project_name))
            except Exception as e:
                log.warning(f"Failed to parse {gemfile_lock}: {e}")

        # ── Composer: composer.lock ────────────────────────────────────────────
        # Ported from bumblebee internal/ecosystem/composer/composer.go
        for composer_lock in project.rglob("composer.lock"):
            if ".claude" in composer_lock.parts:
                continue
            try:
                data = json.loads(composer_lock.read_text())
                for section in ("packages", "packages-dev"):
                    for pkg in data.get(section, []):
                        name    = pkg.get("name", "").lower()
                        version = pkg.get("version", "")
                        if name and version:
                            result["composer"].setdefault(name, []).append((version, project_name))
            except Exception as e:
                log.warning(f"Failed to parse {composer_lock}: {e}")

    counts = ", ".join(f"{k}={len(v)}" for k, v in sorted(result.items()) if v)
    log.info(f"Installed versions scanned: {counts or 'nothing found'}")
    return result


# ── Advisory model ────────────────────────────────────────────────────────────
class Advisory:
    def __init__(self, id: str, source: str, title: str, description: str,
                 severity: str, url: str, published: str,
                 packages: list[str] | None = None,
                 affected_ranges: list[dict] | None = None):
        self.id              = id
        self.source          = source
        self.title           = title
        self.description     = description
        self.severity        = severity.upper() if severity else "UNKNOWN"
        self.url             = url
        self.published       = published
        self.packages        = packages or []
        # Each entry: {"ecosystem": "npm"|"pypi", "name": str, "specifier": str, "fixed": str|None}
        # specifier is a packaging.SpecifierSet-compatible string e.g. ">= 0.0.0, < 1.7.4"
        self.affected_ranges = affected_ranges or []


# ── Exposure checking ─────────────────────────────────────────────────────────
def check_exposure(advisory: Advisory,
                   installed: dict[str, dict[str, list[tuple[str, str]]]]
                   ) -> list[dict]:
    """
    Compare this advisory's affected_ranges against installed package versions.
    Returns list of hits: {"pkg", "version", "project", "fix", "exposed"}
    exposed = True | False | None (None = version parse failed)
    """
    hits = []
    seen = set()  # avoid duplicate hits for the same pkg+version+project

    for ar in advisory.affected_ranges:
        eco      = ar["ecosystem"]
        name     = ar["name"]
        specifier = ar["specifier"]
        fix      = ar.get("fixed")

        # Go module versions use "v"-prefixed semver (e.g. v1.2.3).
        # Strip the prefix from specifiers so packaging.SpecifierSet can parse them.
        if eco == "go":
            specifier = re.sub(r'\bv(\d+\.\d+)', r'\1', specifier)

        # GitHub's vulnerable_version_range uses a bare "=" for exact matches
        # (e.g. "= 3.4.4"), which is NOT valid PEP 440 — packaging needs "==".
        # Normalize any token-initial single "=" to "==" so SpecifierSet parses
        # it instead of raising InvalidSpecifier (which silently voids the check).
        specifier = re.sub(r'(?<![<>=!])=(?!=)', '==', specifier)

        installed_entries = installed.get(eco, {}).get(name, [])
        if not installed_entries:
            continue  # package not installed in any project

        try:
            spec_set = SpecifierSet(specifier, prereleases=True)
        except InvalidSpecifier:
            spec_set = None

        for version_str, project in installed_entries:
            # Strip Go "v" prefix from installed version strings before comparison
            if eco == "go" and version_str.startswith("v"):
                version_str = version_str[1:]
            key = (name, version_str, project)
            if key in seen:
                continue
            seen.add(key)

            exposed: bool | None = None
            if spec_set is not None:
                try:
                    exposed = Version(version_str) in spec_set
                except InvalidVersion:
                    pass

            hits.append({"pkg": name, "version": version_str,
                         "project": project, "fix": fix, "exposed": exposed})

    return hits


# ── Fetchers ──────────────────────────────────────────────────────────────────
def _osv_events_to_specifier(events: list[dict]) -> tuple[str, str | None]:
    """
    Convert OSV SEMVER events list to a SpecifierSet-compatible string.
    Returns (specifier_str, fixed_version_or_None).
    """
    introduced = None
    fixed      = None
    for ev in events:
        if "introduced" in ev:
            introduced = ev["introduced"]
        if "fixed" in ev:
            fixed = ev["fixed"]

    parts = []
    if introduced and introduced not in ("0", "0.0.0"):
        parts.append(f">= {introduced}")
    else:
        parts.append(">= 0.0.0")
    if fixed:
        parts.append(f"< {fixed}")

    return ", ".join(parts), fixed


def fetch_cisa() -> list[Advisory]:
    advisories = []
    try:
        resp = httpx.get(
            "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            timeout=30, follow_redirects=True,
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.content)

        for item in root.findall(".//item"):
            title       = item.findtext("title", "").strip()
            link        = item.findtext("link", "").strip()
            description = item.findtext("description", "").strip()
            pub_date    = item.findtext("pubDate", "").strip()
            guid        = item.findtext("guid", link).strip()

            # CISA advisories are platform/product advisories — no structured
            # version data in the RSS feed, so affected_ranges stays empty.
            advisories.append(Advisory(
                id          = f"cisa:{guid}",
                source      = "CISA",
                title       = title,
                description = description[:2000],
                severity    = "UNKNOWN",
                url         = link,
                published   = pub_date,
            ))
    except Exception as e:
        log.error(f"CISA fetch failed: {e}")

    log.info(f"CISA: {len(advisories)} advisories fetched")
    return advisories


def fetch_github_blog() -> list[Advisory]:
    advisories = []
    try:
        resp = httpx.get(
            "https://github.blog/tag/security/feed/",
            timeout=30, follow_redirects=True,
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.content)

        for item in root.findall(".//item"):
            title       = item.findtext("title", "").strip()
            link        = item.findtext("link", "").strip()
            description = item.findtext("description", "").strip()
            pub_date    = item.findtext("pubDate", "").strip()
            guid        = item.findtext("guid", link).strip()

            advisories.append(Advisory(
                id          = f"ghblog:{guid}",
                source      = "GitHub Blog",
                title       = title,
                description = description[:2000],
                severity    = "UNKNOWN",
                url         = link,
                published   = pub_date,
            ))
    except Exception as e:
        log.error(f"GitHub Blog fetch failed: {e}")

    log.info(f"GitHub Blog: {len(advisories)} posts fetched")
    return advisories


def fetch_bleeping_computer() -> list[Advisory]:
    advisories = []
    try:
        resp = httpx.get(
            "https://www.bleepingcomputer.com/feed/",
            timeout=30, follow_redirects=True,
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.content)

        for item in root.findall(".//item"):
            title       = item.findtext("title", "").strip()
            link        = item.findtext("link", "").strip()
            description = item.findtext("description", "").strip()
            pub_date    = item.findtext("pubDate", "").strip()
            guid        = item.findtext("guid", link).strip()

            advisories.append(Advisory(
                id          = f"bc:{guid}",
                source      = "Bleeping Computer",
                title       = title,
                description = description[:2000],
                severity    = "UNKNOWN",
                url         = link,
                published   = pub_date,
            ))
    except Exception as e:
        log.error(f"Bleeping Computer fetch failed: {e}")

    log.info(f"Bleeping Computer: {len(advisories)} posts fetched")
    return advisories


def fetch_krebs() -> list[Advisory]:
    advisories = []
    try:
        resp = httpx.get(
            "https://krebsonsecurity.com/feed/",
            timeout=30, follow_redirects=True,
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.content)

        for item in root.findall(".//item"):
            title       = item.findtext("title", "").strip()
            link        = item.findtext("link", "").strip()
            description = item.findtext("description", "").strip()
            pub_date    = item.findtext("pubDate", "").strip()
            guid        = item.findtext("guid", link).strip()

            advisories.append(Advisory(
                id          = f"krebs:{guid}",
                source      = "Krebs on Security",
                title       = title,
                description = description[:2000],
                severity    = "UNKNOWN",
                url         = link,
                published   = pub_date,
            ))
    except Exception as e:
        log.error(f"Krebs fetch failed: {e}")

    log.info(f"Krebs on Security: {len(advisories)} posts fetched")
    return advisories


def fetch_github_advisories(since: datetime | None) -> list[Advisory]:
    advisories = []
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    params: dict = {"per_page": 100, "sort": "published", "direction": "desc", "type": "reviewed"}
    if since:
        params["published"] = f">{since.strftime('%Y-%m-%dT%H:%M:%SZ')}"

    try:
        resp = httpx.get(
            "https://api.github.com/advisories",
            headers=headers, params=params, timeout=30,
        )
        resp.raise_for_status()

        for item in resp.json():
            packages        = []
            affected_ranges = []

            for vuln in item.get("vulnerabilities", []):
                pkg = vuln.get("package", {})
                if not pkg.get("name"):
                    continue

                eco      = _normalize_eco(pkg.get("ecosystem", ""))
                pkg_name = pkg["name"].lower()
                packages.append(f"{pkg.get('ecosystem', '?')}/{pkg['name']}")

                # Capture version range for exposure checking (all tracked ecosystems)
                version_range = vuln.get("vulnerable_version_range", "")
                fixed_ver     = vuln.get("first_patched_version")
                if version_range and eco in INTERNAL_TO_OSV_ECO:
                    affected_ranges.append({
                        "ecosystem": eco,
                        "name":      pkg_name,
                        "specifier": version_range,  # close to packaging notation; check_exposure normalizes bare "=" → "=="
                        "fixed":     fixed_ver,
                    })

            advisories.append(Advisory(
                id              = f"ghsa:{item['ghsa_id']}",
                source          = "GitHub Advisory",
                title           = item.get("summary", ""),
                description     = item.get("description", "")[:2000],
                severity        = item.get("severity", "UNKNOWN"),
                url             = item.get("html_url", ""),
                published       = item.get("published_at", ""),
                packages        = packages,
                affected_ranges = affected_ranges,
            ))
    except Exception as e:
        log.error(f"GitHub Advisory fetch failed: {e}")

    log.info(f"GitHub Advisory: {len(advisories)} advisories fetched")
    return advisories


def fetch_osv(installed: dict[str, dict[str, list[tuple[str, str]]]]) -> list[Advisory]:
    """Batch-query OSV for all packages in the stack across all tracked ecosystems."""
    queries = []
    for eco_key, osv_eco in INTERNAL_TO_OSV_ECO.items():
        for pkg in installed.get(eco_key, {}):
            queries.append({"package": {"name": pkg, "ecosystem": osv_eco}})

    if not queries:
        return []

    advisories: list[Advisory] = []
    seen_osv_ids: set[str]     = set()

    for chunk_start in range(0, len(queries), 1000):
        chunk = queries[chunk_start:chunk_start + 1000]
        try:
            resp = httpx.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": chunk},
                timeout=60,
            )
            resp.raise_for_status()

            for result in resp.json().get("results", []):
                for vuln in result.get("vulns", []):
                    vid = vuln.get("id", "")
                    if not vid or vid in seen_osv_ids:
                        continue
                    seen_osv_ids.add(vid)

                    # Severity
                    severity    = "UNKNOWN"
                    db_specific = vuln.get("database_specific", {})
                    if isinstance(db_specific.get("severity"), str):
                        severity = db_specific["severity"].upper()

                    if severity == "UNKNOWN":
                        for sev_entry in vuln.get("severity", []):
                            score_str = sev_entry.get("score", "")
                            try:
                                base = float(score_str.rsplit("/", 1)[-1])
                                if base >= 9.0:   severity = "CRITICAL"
                                elif base >= 7.0: severity = "HIGH"
                                elif base >= 4.0: severity = "MEDIUM"
                                else:             severity = "LOW"
                                break
                            except (ValueError, IndexError):
                                pass

                    # Packages + affected version ranges
                    packages        = []
                    affected_ranges = []

                    for affected in vuln.get("affected", []):
                        pkg = affected.get("package", {})
                        if not pkg.get("name"):
                            continue

                        eco_raw  = pkg.get("ecosystem", "")
                        eco      = _normalize_eco(eco_raw)
                        pkg_name = pkg["name"].lower()
                        packages.append(f"{eco_raw}/{pkg['name']}")

                        if eco not in INTERNAL_TO_OSV_ECO:
                            continue

                        for rng in affected.get("ranges", []):
                            if rng.get("type") != "SEMVER":
                                continue
                            specifier, fixed = _osv_events_to_specifier(rng.get("events", []))
                            affected_ranges.append({
                                "ecosystem": eco,
                                "name":      pkg_name,
                                "specifier": specifier,
                                "fixed":     fixed,
                            })

                    advisories.append(Advisory(
                        id              = f"osv:{vid}",
                        source          = "OSV",
                        title           = vuln.get("summary", vid),
                        description     = vuln.get("details", vuln.get("summary", ""))[:2000],
                        severity        = severity,
                        url             = f"https://osv.dev/vulnerability/{vid}",
                        published       = vuln.get("published", ""),
                        packages        = packages,
                        affected_ranges = affected_ranges,
                    ))
        except Exception as e:
            log.error(f"OSV batch query failed (chunk {chunk_start}): {e}")

    log.info(f"OSV: {len(advisories)} unique advisories fetched")
    return advisories


# ── Relevance scoring ─────────────────────────────────────────────────────────
def score_relevance(advisories: list[Advisory], stack_context: str) -> list[tuple[Advisory, str, str]]:
    """
    Ask Claude (Haiku) to assess relevance and confirm severity.
    Returns (advisory, reason, confirmed_severity) for relevant ones only.
    """
    if not advisories:
        return []

    entries = [
        {
            "index":       i,
            "source":      a.source,
            "title":       a.title,
            "severity":    a.severity,
            "packages":    a.packages[:10],
            "description": a.description[:600],
        }
        for i, a in enumerate(advisories)
    ]

    system = f"""You are a security analyst reviewing vulnerability advisories for a solo developer.

{stack_context}

For each advisory, output a JSON array where every element has:
- "index": integer (the advisory's index)
- "relevant": true if it directly affects a package, platform, runtime, or service in the stack above; false otherwise
- "severity": CRITICAL | HIGH | MEDIUM | LOW (confirm or correct the given severity based on the description)
- "reason": one concise sentence — if relevant, why it matters to this stack; if not, why not

Be strict: only mark relevant=true if action may be required. Generic advisories about technologies not in the stack are irrelevant.

Respond with ONLY the JSON array, no other text."""

    BATCH_SIZE   = 25
    all_relevant: list[tuple[Advisory, str, str]] = []

    for batch_start in range(0, len(entries), BATCH_SIZE):
        batch = entries[batch_start:batch_start + BATCH_SIZE]
        try:
            response = anthropic.messages.create(
                model="claude-haiku-4-5",
                max_tokens=4096,
                system=system,
                messages=[{"role": "user", "content": json.dumps(batch, indent=2)}],
            )
            raw_text = response.content[0].text.strip()
            # Strip markdown code fences if the model wrapped the response
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            results = json.loads(raw_text)

            for r in results:
                if r.get("relevant"):
                    adv = advisories[r["index"]]
                    all_relevant.append((adv, r["reason"], r["severity"].upper()))

        except Exception as e:
            log.error(f"Relevance scoring failed (batch {batch_start}–{batch_start + BATCH_SIZE}): {e}")

    log.info(f"Relevance: {len(all_relevant)}/{len(advisories)} marked relevant")
    return all_relevant


# ── Email ─────────────────────────────────────────────────────────────────────
SEVERITY_COLOUR = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#d4ac0d",
}
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
}


def _exposure_html(hits: list[dict], source: str = "", has_ranges: bool = False) -> str:
    """Render the exposure block for one advisory."""
    if not hits:
        if source in ("CISA", "GitHub Blog", "Bleeping Computer", "Krebs on Security"):
            msg = ("ℹ️ <strong>Exposure check not applicable</strong> — this is a service/incident advisory, "
                   "not a package vulnerability; no version data to compare against your stack.")
        elif has_ranges:
            msg = ("✅ <strong>Not installed</strong> — affected package is not present in any scanned project.")
        else:
            msg = ("ℹ️ <strong>No version data</strong> — affected packages are not in a tracked ecosystem; "
                   "cannot perform automated version check.")
        return f'<p style="background:#f0f0f0;padding:10px;border-radius:4px;margin:8px 0">{msg}</p>'

    exposed     = [h for h in hits if h["exposed"] is True]
    not_exposed = [h for h in hits if h["exposed"] is False]

    if exposed:
        rows = ""
        for h in exposed:
            fix_str = f" → update to <strong>{h['fix']}</strong>" if h["fix"] else " <em>(no fix available yet)</em>"
            rows += f"<li><code>{h['pkg']}@{h['version']}</code> in <strong>{h['project']}</strong>{fix_str}</li>"
        return (f'<div style="background:#fde8e8;padding:10px 14px;border-radius:4px;margin:8px 0">'
                f'⚠️ <strong>YOU ARE EXPOSED</strong><ul style="margin:6px 0 0">{rows}</ul></div>')

    if not_exposed:
        pkgs = ", ".join(f"{h['pkg']}@{h['version']}" for h in not_exposed[:5])
        return (f'<p style="background:#e8f8e8;padding:10px;border-radius:4px;margin:8px 0">'
                f'✅ <strong>Not exposed</strong> — installed versions ({pkgs}) are outside the affected range.</p>')

    # hits exist but all have exposed=None (version parse failed)
    return ('<p style="background:#f0f0f0;padding:10px;border-radius:4px;margin:8px 0">'
            'ℹ️ <strong>Exposure uncertain</strong> — found affected packages installed but could not compare versions.</p>')


def _exposure_text(hits: list[dict], source: str = "", has_ranges: bool = False) -> str:
    if not hits:
        if source in ("CISA", "GitHub Blog", "Bleeping Computer", "Krebs on Security"):
            return "Exposure check not applicable — service/incident advisory; no package version data."
        if has_ranges:
            return "Not installed — affected package is not present in any scanned project."
        return "No version data — affected packages are not in a tracked ecosystem."
    exposed = [h for h in hits if h["exposed"] is True]
    if exposed:
        lines = ["⚠️  YOU ARE EXPOSED:"]
        for h in exposed:
            fix = f" → update to {h['fix']}" if h["fix"] else " (no fix yet)"
            lines.append(f"   {h['pkg']}@{h['version']} in {h['project']}{fix}")
        return "\n".join(lines)
    not_exposed = [h for h in hits if h["exposed"] is False]
    if not_exposed:
        pkgs = ", ".join(f"{h['pkg']}@{h['version']}" for h in not_exposed[:5])
        return f"✅ Not exposed — installed versions ({pkgs}) are outside the affected range."
    return "Exposure: uncertain (could not compare versions)"


def _advisory_html(adv: Advisory, reason: str, severity: str, hits: list[dict]) -> str:
    colour   = SEVERITY_COLOUR.get(severity, "#888")
    emoji    = SEVERITY_EMOJI.get(severity, "⚪")
    pkgs     = ", ".join(adv.packages[:10]) if adv.packages else "—"
    exposure = _exposure_html(hits, source=adv.source, has_ranges=bool(adv.affected_ranges))
    return f"""
<div style="border-left:4px solid {colour}; padding:12px 16px; margin:16px 0; background:#fafafa;">
  <h3 style="margin:0 0 4px; color:{colour}">{emoji} [{severity}] {adv.source}</h3>
  <p style="margin:0 0 8px; font-size:16px; font-weight:bold">{adv.title}</p>
  {exposure}
  <p><strong>Why this matters:</strong> {reason}</p>
  <p><strong>Affected packages:</strong> {pkgs}</p>
  <p><strong>Published:</strong> {adv.published}</p>
  <p style="color:#555">{adv.description}</p>
  <p><a href="{adv.url}">View full advisory →</a></p>
</div>"""


# ── Automated investigation ───────────────────────────────────────────────────
def _extract_cve(adv: Advisory) -> str | None:
    text = f"{adv.title} {adv.description} {adv.url}"
    m = re.search(r'CVE-\d{4}-\d+', text, re.IGNORECASE)
    return m.group(0).upper() if m else None


def generate_investigation(adv: Advisory, hits: list[dict],
                           reason: str, severity: str) -> dict:
    """
    Call Claude Sonnet to produce a structured investigation.
    Returns dict with: impact_summary, proposed_action, upgrade_commands, confidence.
    """
    exposed     = [h for h in hits if h["exposed"] is True]
    not_exposed = [h for h in hits if h["exposed"] is False]
    uncertain   = [h for h in hits if h["exposed"] is None]

    if exposed:
        exposure_summary = "EXPOSED: " + "; ".join(
            f"{h['pkg']}@{h['version']} in {h['project']} (fix: {h['fix'] or 'unknown'})"
            for h in exposed
        )
    elif uncertain:
        exposure_summary = "UNCERTAIN — package installed but version could NOT be compared (treat as possibly affected, do NOT assume safe): " + "; ".join(
            f"{h['pkg']}@{h['version']} in {h['project']} (fix if affected: {h['fix'] or 'unknown'})"
            for h in uncertain
        )
    elif not_exposed:
        exposure_summary = "Not exposed: " + "; ".join(
            f"{h['pkg']}@{h['version']} in {h['project']}"
            for h in not_exposed
        )
    else:
        exposure_summary = "No installed packages matched the affected range."

    # Resolve each installed match to its real project root so the model targets
    # the ACTUAL install location instead of guessing a plausible project.
    try:
        stack_cfg = yaml.safe_load(STACK_FILE.read_text())
        path_by_name = {
            Path(p).expanduser().name: str(Path(p).expanduser())
            for p in stack_cfg.get("project_paths", [])
        }
    except Exception:
        path_by_name = {}

    all_hits = exposed + uncertain + not_exposed
    if all_hits:
        installed_locations = "\n".join(
            f"- {h['pkg']}@{h['version']} found in project '{h['project']}' "
            f"(root: {path_by_name.get(h['project'], '~/' + h['project'])})"
            for h in all_hits
        )
    else:
        installed_locations = "(none — the scan found no copy of the affected package in any project_path)"

    prompt = f"""Advisory: [{severity}] {adv.source}: {adv.title}
URL: {adv.url}
Published: {adv.published}
Affected packages: {', '.join(adv.packages[:10]) or '—'}
Relevance reason: {reason}
Exposure check: {exposure_summary}

Installed locations (authoritative — from the dependency scan, NOT a guess):
{installed_locations}

Description:
{adv.description[:1500]}

Produce a JSON object with these fields:
- "impact_summary": 2-3 sentence plain-English assessment of the real risk to this stack
- "proposed_action": one clear sentence — "No action required" (with reason) or a specific remediation step
- "check_commands": list of read-only shell commands that verify whether the system is actually affected right now. CRITICAL: target ONLY the project roots listed under "Installed locations" above — do NOT invent or guess other projects. If Installed locations is "(none)", the package was not found by the scan, so prefer an empty list over guessing where it might be. Commands run automatically and must be safe, non-destructive, and human-readable. Empty list if no meaningful check is possible.
- "upgrade_commands": list of shell commands to remediate, using the full project roots from "Installed locations" above. Empty list if no action needed.
- "confidence": "HIGH" | "MEDIUM" | "LOW" — confidence in this assessment

Respond with ONLY the JSON object, no other text."""

    try:
        response = anthropic.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
        return json.loads(raw)
    except Exception as e:
        log.error(f"Investigation failed for {adv.id}: {e}")
        return {
            "impact_summary": "Automated investigation failed — review advisory manually.",
            "proposed_action": "Manual review required.",
            "upgrade_commands": [],
            "confidence": "LOW",
        }


def run_check_commands(commands: list[str]) -> list[dict]:
    """
    Run each read-only check command and return results.
    Each result: {"command": str, "stdout": str, "stderr": str, "returncode": int}
    """
    results = []
    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15,
                env={**os.environ, "HOME": str(Path.home())},
            )
            results.append({
                "command":    cmd,
                "stdout":     proc.stdout.strip()[:2000],
                "stderr":     proc.stderr.strip()[:500],
                "returncode": proc.returncode,
            })
            log.info(f"Check command rc={proc.returncode}: {cmd[:60]}")
        except subprocess.TimeoutExpired:
            results.append({"command": cmd, "stdout": "", "stderr": "timed out after 15s", "returncode": -1})
            log.warning(f"Check command timed out: {cmd[:60]}")
        except Exception as e:
            results.append({"command": cmd, "stdout": "", "stderr": str(e), "returncode": -1})
            log.warning(f"Check command failed: {cmd[:60]}: {e}")
    return results


def write_triage_file(adv: Advisory, hits: list[dict], investigation: dict,
                      severity: str, reason: str) -> str:
    """Write a triage markdown file to triage/. Skips if file already exists. Returns filename."""
    TRIAGE_DIR.mkdir(exist_ok=True)

    cve = _extract_cve(adv)
    filename = f"{cve}.md" if cve else f"{re.sub(r'[^a-zA-Z0-9_-]', '_', adv.id)[:60]}.md"
    triage_file = TRIAGE_DIR / filename

    if triage_file.exists():
        log.info(f"Triage file already exists, skipping: {filename}")
        return filename

    exposed     = [h for h in hits if h["exposed"] is True]
    not_exposed = [h for h in hits if h["exposed"] is False]
    uncertain   = [h for h in hits if h["exposed"] is None]

    if exposed:
        status = "⚠️ Exposed"
        exposure_md = "\n".join(
            f"- `{h['pkg']}@{h['version']}` in **{h['project']}** — fix: `{h['fix'] or 'unknown'}`"
            for h in exposed
        )
    elif uncertain:
        # Package IS installed but its version could not be compared against the
        # affected range (e.g. unparseable specifier). This is UNKNOWN, not safe —
        # surface it loudly rather than silently treating it as "not installed".
        status = "❓ Exposure uncertain — MANUAL REVIEW"
        exposure_md = "\n".join(
            f"- `{h['pkg']}@{h['version']}` in **{h['project']}** — installed, but version "
            f"could not be compared against the affected range (fix if affected: `{h['fix'] or 'unknown'}`)"
            for h in uncertain
        )
    elif not_exposed:
        status = "✅ Not affected"
        exposure_md = "\n".join(
            f"- `{h['pkg']}@{h['version']}` in **{h['project']}** — outside affected range"
            for h in not_exposed
        )
    elif adv.affected_ranges:
        status = "✅ Not installed"
        exposure_md = "Affected package is not present in any scanned project."
    else:
        status = "❓ Unknown"
        exposure_md = "Affected packages are not in a tracked ecosystem; no automated version check performed."

    commands_section = ""
    cmds = investigation.get("upgrade_commands", [])
    if cmds:
        commands_section = "\n## Remediation Commands\n\n```sh\n" + "\n".join(cmds) + "\n```\n"

    refs = f"- {adv.url}\n"
    if cve:
        refs += f"- https://nvd.nist.gov/vuln/detail/{cve}\n"

    content = f"""# {adv.title}

**Advisory ID:** {adv.id}
**Date reviewed:** {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
**Source:** {adv.source} · **Severity:** {severity}
**Status:** {status} · **Confidence:** {investigation.get('confidence', '—')}

## Summary

{investigation.get('impact_summary', adv.description[:500])}

## Exposure

{exposure_md}

## Proposed Action

{investigation.get('proposed_action', '—')}
{commands_section}
## Why Flagged

{reason}

## Resolution

_No action taken yet._

## References

{refs}"""

    triage_file.write_text(content)
    log.info(f"Triage file written: {filename}")
    return filename


def update_recent(new_entries: list[dict]):
    """Prepend new alert entries to recent.json and rewrite RECENT.md. Keeps last MAX_RECENT."""
    TRIAGE_DIR.mkdir(exist_ok=True)
    existing: list[dict] = []
    if RECENT_JSON.exists():
        try:
            existing = json.loads(RECENT_JSON.read_text())
        except Exception:
            pass
    combined = (new_entries + existing)[:MAX_RECENT]
    RECENT_JSON.write_text(json.dumps(combined, indent=2))

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = "".join(
        f"| {e['date']} | {e['severity']} | {e['title'][:65]} | [{e['filename']}]({e['filename']}) |\n"
        for e in combined
    )
    RECENT_MD.write_text(
        f"# Recent Alerts\n\n_Last updated: {now_str}_\n\n"
        f"| Date (UTC) | Severity | Title | Triage File |\n"
        f"|---|---|---|---|\n"
        f"{rows}"
    )
    log.info(f"RECENT.md updated ({len(combined)} entries)")


def _investigation_html(investigation: dict, check_results: list[dict] | None = None) -> str:
    action   = investigation.get("proposed_action", "—")
    summary  = investigation.get("impact_summary", "")
    cmds     = investigation.get("upgrade_commands", [])
    conf     = investigation.get("confidence", "—")

    checks_html = ""
    if check_results:
        rows = ""
        for r in check_results:
            output = r["stdout"] or r["stderr"] or "(no output)"
            rc_color = "#c0392b" if r["returncode"] not in (0, 1) else "#333"
            rows += (
                f'<div style="margin:6px 0">'
                f'<code style="background:#e8e8e8;padding:2px 5px;border-radius:3px">{r["command"]}</code>'
                f'<pre style="margin:4px 0 0;background:#f8f8f8;padding:8px;border-radius:3px;'
                f'font-size:12px;overflow-x:auto;color:{rc_color}">{output}</pre>'
                f'</div>'
            )
        checks_html = (
            f'<p style="margin:8px 0 4px"><strong>✅ Live checks run:</strong></p>'
            f'{rows}'
        )

    cmd_html = ""
    if cmds:
        cmd_list = "".join(f"<li><code>{c}</code></li>" for c in cmds)
        cmd_html = f"<p><strong>Remediation commands:</strong></p><ul>{cmd_list}</ul>"

    return f"""
<div style="background:#f0f4ff;border-left:4px solid #3b5bdb;padding:12px 16px;margin:12px 0;border-radius:0 4px 4px 0">
  <p style="margin:0 0 6px"><strong>🔍 Investigation (confidence: {conf})</strong></p>
  <p style="margin:0 0 6px">{summary}</p>
  <p style="margin:0 0 4px"><strong>Proposed action:</strong> {action}</p>
  {checks_html}
  {cmd_html}
</div>"""


def _is_no_action_needed(adv: Advisory, hits: list[dict]) -> bool:
    """True when this package advisory has a definitive "you're fine, no action"
    answer — either the affected package is not installed, or it is installed but
    every installed version sits outside the affected range.

    Withholds the email in both the "Not installed" and "Not affected" cases, which
    are the bulk of the inbox noise. Still emails when:
      - affected_ranges is empty — a service/incident advisory (CISA, GitHub Blog,
        Bleeping, Krebs) with no version data to clear it; always surfaced.
      - any installed version is actually exposed (exposed is True).
      - exposure is uncertain (exposed is None — version parse failed); we fail loud
        and email rather than silently clearing something we couldn't evaluate.

    Suppressed advisories still get full investigation, live checks, triage files,
    RECENT.md entries and log lines — only the email is withheld.
    """
    if not adv.affected_ranges:
        return False              # incident/service advisory — no version data to clear it
    if not hits:
        return True               # affected package not installed in any scanned project
    return all(h["exposed"] is False for h in hits)  # installed, but every version is safe


def send_alerts(to_notify: list[tuple[Advisory, str, str]],
                installed: dict[str, dict[str, list[tuple[str, str]]]]) -> tuple[int, int]:
    """
    Send individual emails for CRITICAL/HIGH.
    Batch MEDIUMs into a single digest.
    Subject line is prefixed with ⚠️ EXPOSED when exposure is confirmed.

    Advisories with a definitive no-action verdict (affected package not installed,
    or installed but on a safe version) are investigated and logged in full but
    generate no email. Returns (emails_sent, advisories_suppressed).
    """
    critical_high = [(a, r, s) for a, r, s in to_notify if s in ("CRITICAL", "HIGH")]
    medium        = [(a, r, s) for a, r, s in to_notify if s == "MEDIUM"]
    recent_entries: list[dict] = []
    emails_sent  = 0
    suppressed   = 0

    for adv, reason, severity in critical_high:
        hits          = check_exposure(adv, installed)
        investigation = generate_investigation(adv, hits, reason, severity)
        check_results = run_check_commands(investigation.get("check_commands", []))
        filename      = write_triage_file(adv, hits, investigation, severity, reason)

        # Triage file + RECENT.md entry are written regardless of whether we email,
        # so the investigative trail is preserved for every advisory.
        if filename:
            recent_entries.append({
                "date":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
                "severity": severity,
                "title":    adv.title,
                "filename": filename,
            })

        if _is_no_action_needed(adv, hits):
            suppressed += 1
            log.info(f"Email suppressed (no action needed — not installed or not affected): "
                     f"[{severity}] {adv.id} — {adv.title[:70]}")
            continue

        is_exposed  = any(h["exposed"] is True for h in hits)
        emoji       = SEVERITY_EMOJI.get(severity, "⚪")
        exposed_tag = "⚠️ EXPOSED · " if is_exposed else ""
        subject     = f"{exposed_tag}{emoji} [{severity}] {adv.source}: {adv.title[:70]}"

        inv_text = (f"\n--- Investigation (confidence: {investigation.get('confidence','—')}) ---\n"
                    f"{investigation.get('impact_summary','')}\n\n"
                    f"Proposed action: {investigation.get('proposed_action','—')}\n")
        if check_results:
            inv_text += "\nLive checks:\n"
            for r in check_results:
                output = r["stdout"] or r["stderr"] or "(no output)"
                inv_text += f"  $ {r['command']}\n    {output[:300]}\n"
        cmds = investigation.get("upgrade_commands", [])
        if cmds:
            inv_text += "Remediation commands:\n" + "\n".join(f"  {c}" for c in cmds) + "\n"

        triage_html = (f'<p style="background:#f5f5f5;padding:6px 10px;border-radius:3px;'
                       f'font-family:monospace;font-size:13px">📁 Triage: <code>triage/{filename}</code></p>'
                       ) if filename else ""
        triage_text = f"\nTriage: triage/{filename}\n" if filename else ""

        html = f"""<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:700px;margin:0 auto;padding:20px">
  <h2 style="color:{SEVERITY_COLOUR.get(severity,'#333')}">Security Alert</h2>
  {_advisory_html(adv, reason, severity, hits)}
  {triage_html}
  {_investigation_html(investigation, check_results)}
  <p style="color:#999;font-size:12px;margin-top:32px">Security Monitor · every 60 min</p>
</body></html>"""

        text = (f"[{severity}] {adv.source}: {adv.title}\n\n"
                f"{_exposure_text(hits, source=adv.source, has_ranges=bool(adv.affected_ranges))}\n"
                f"{inv_text}"
                f"{triage_text}\n"
                f"Why this matters: {reason}\n"
                f"Packages: {', '.join(adv.packages[:10]) or '—'}\n"
                f"Published: {adv.published}\n\n"
                f"{adv.description}\n\n{adv.url}")
        _send(subject, html, text)
        emails_sent += 1

    if medium:
        any_exposed     = False
        bodies          = []
        text_parts      = []
        triage_filenames: list[str] = []
        included = 0
        for adv, reason, severity in medium:
            hits          = check_exposure(adv, installed)
            investigation = generate_investigation(adv, hits, reason, severity)
            check_results = run_check_commands(investigation.get("check_commands", []))
            filename      = write_triage_file(adv, hits, investigation, severity, reason)

            # Triage file + RECENT.md entry are recorded for every advisory, even
            # those whose email we suppress, so the investigative trail is preserved.
            if filename:
                recent_entries.append({
                    "date":     datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
                    "severity": severity,
                    "title":    adv.title,
                    "filename": filename,
                })

            if _is_no_action_needed(adv, hits):
                suppressed += 1
                log.info(f"Digest entry suppressed (no action needed — not installed or not affected): "
                         f"[{severity}] {adv.id} — {adv.title[:70]}")
                continue

            included += 1
            if any(h["exposed"] is True for h in hits):
                any_exposed = True
            bodies.append(_advisory_html(adv, reason, severity, hits) +
                          _investigation_html(investigation, check_results))
            text_parts.append(
                f"[MEDIUM] {adv.source}: {adv.title}\n"
                f"{_exposure_text(hits, source=adv.source, has_ranges=bool(adv.affected_ranges))}\nWhy: {reason}\n{adv.url}"
            )
            if filename:
                triage_filenames.append(filename)

        # If every MEDIUM advisory was a not-installed/no-action case, send nothing.
        if not bodies:
            log.info("MEDIUM digest skipped — all advisories were no-action (not installed / not affected).")
        else:
            exposed_tag = "⚠️ EXPOSED · " if any_exposed else ""
            subject = (f"{exposed_tag}🟡 [MEDIUM] "
                       f"{included} security advisory{'s' if included > 1 else ''} — action may be needed")

            triage_list_html = ""
            if triage_filenames:
                items = "".join(f"<li><code>triage/{f}</code></li>" for f in triage_filenames)
                triage_list_html = (f'<p style="background:#f5f5f5;padding:6px 10px;border-radius:3px;'
                                    f'font-family:monospace;font-size:13px">📁 Triage files:<ul style="margin:4px 0">'
                                    f'{items}</ul></p>')
            triage_list_text = ("\nTriage files:\n" + "\n".join(f"  triage/{f}" for f in triage_filenames) + "\n"
                                ) if triage_filenames else ""

            html = f"""<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:700px;margin:0 auto;padding:20px">
  <h2 style="color:{SEVERITY_COLOUR['MEDIUM']}">Medium Severity Digest</h2>
  {"".join(bodies)}
  {triage_list_html}
  <p style="color:#999;font-size:12px;margin-top:32px">Security Monitor · every 60 min</p>
</body></html>"""
            _send(subject, html, "\n\n---\n\n".join(text_parts) + triage_list_text)
            emails_sent += 1

    if recent_entries:
        update_recent(recent_entries)

    return emails_sent, suppressed


def _send(subject: str, body_html: str, body_text: str):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = FASTMAIL_USER
    msg["To"]      = FASTMAIL_USER
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))

    with smtplib.SMTP("smtp.fastmail.com", 587) as server:
        server.ehlo()
        server.starttls()
        server.login(FASTMAIL_USER, FASTMAIL_APP_PASSWORD)
        server.sendmail(FASTMAIL_USER, FASTMAIL_USER, msg.as_string())

    log.info(f"Email sent: {subject[:80]}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    log.info("=== Security Monitor run started ===")

    # ── test mode ─────────────────────────────────────────────────────────────
    if "--test" in sys.argv:
        log.info("Test mode: sending test email...")
        _send(
            subject   = "🔧 Security Monitor — connectivity test",
            body_html = "<p>Security monitor is correctly configured. Email delivery is working.</p>",
            body_text = "Security monitor is correctly configured. Email delivery is working.",
        )
        log.info("Test email sent successfully.")
        sys.exit(0)

    state    = load_state()
    seen_ids = set(state.get("seen_ids", []))

    last_run_str = state.get("last_run")
    since: datetime | None = None
    if last_run_str:
        since = datetime.fromisoformat(last_run_str)
    else:
        log.info("First run — looking back 4 hours for recent advisories")
        since = datetime.now(timezone.utc) - timedelta(hours=4)

    # ── Build installed versions first (needed for stack context and OSV queries) ─
    log.info("Scanning installed package versions...")
    installed = build_installed_versions()

    # Build stack context for Haiku relevance scoring
    stack_context = build_stack_context(installed=installed)

    # Supplement installed with any package.json/requirements.txt entries not in lockfiles
    # (important for packages declared but not yet resolved to a lockfile)
    augmented = {eco: dict(pkgs) for eco, pkgs in installed.items()}
    stack_cfg = yaml.safe_load(STACK_FILE.read_text())
    for raw_path in stack_cfg.get("project_paths", []):
        project = Path(raw_path).expanduser()
        for pkg_file in project.rglob("package.json"):
            if "node_modules" in pkg_file.parts or ".claude" in pkg_file.parts:
                continue
            try:
                data = json.loads(pkg_file.read_text())
                for section in ("dependencies", "devDependencies"):
                    for pkg in data.get(section, {}):
                        augmented.setdefault("npm", {}).setdefault(pkg.lower(), [])
            except Exception:
                pass
        for req_file in project.rglob("requirements.txt"):
            if ".claude" in req_file.parts:
                continue
            try:
                for line in req_file.read_text().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    pkg = line.split("==")[0].split(">=")[0].split("<=")[0] \
                               .split("~=")[0].split("[")[0].split(";")[0].strip()
                    if pkg:
                        augmented.setdefault("pypi", {}).setdefault(pkg.lower(), [])
            except Exception:
                pass

    eco_summary = ", ".join(f"{k}={len(v)}" for k, v in sorted(augmented.items()))
    log.info(f"Stack: {eco_summary}, context={len(stack_context)} chars")

    # ── Fetch ──────────────────────────────────────────────────────────────────
    all_advisories: list[Advisory] = []
    all_advisories.extend(fetch_cisa())
    all_advisories.extend(fetch_github_blog())
    all_advisories.extend(fetch_bleeping_computer())
    all_advisories.extend(fetch_krebs())
    all_advisories.extend(fetch_github_advisories(since))
    all_advisories.extend(fetch_osv(augmented))

    new_advisories = [a for a in all_advisories if a.id not in seen_ids]
    already_seen_count = len(all_advisories) - len(new_advisories)
    log.info(
        f"Total fetched: {len(all_advisories)}, "
        f"already seen: {already_seen_count}, "
        f"new: {len(new_advisories)} "
        f"(seen_ids in state: {len(seen_ids)})"
    )

    for adv in all_advisories:
        seen_ids.add(adv.id)

    # ── Score relevance ────────────────────────────────────────────────────────
    to_notify: list[tuple[Advisory, str, str]] = []
    if new_advisories:
        candidates = [a for a in new_advisories if SEVERITY_RANK.get(a.severity, 0) >= 2 or a.severity == "UNKNOWN"]
        log.info(f"Candidates for relevance scoring (MEDIUM+ or UNKNOWN): {len(candidates)}")

        if candidates:
            relevant  = score_relevance(candidates, stack_context)
            to_notify = [(a, r, s) for a, r, s in relevant if SEVERITY_RANK.get(s, 0) >= 2]

    # ── Notify ─────────────────────────────────────────────────────────────────
    emails_sent = 0
    suppressed  = 0
    if to_notify:
        log.info(f"Processing {len(to_notify)} relevant advisories...")
        emails_sent, suppressed = send_alerts(to_notify, installed)
    else:
        log.info("No relevant alerts this run.")

    # ── Save state ─────────────────────────────────────────────────────────────
    state["seen_ids"] = list(seen_ids)
    save_state(state)

    log.info(f"=== Run complete. {emails_sent} email(s) sent, "
             f"{suppressed} suppressed (no action — not installed / not affected). "
             f"{len(to_notify)} relevant advisories investigated. ===\n")


if __name__ == "__main__":
    main()
