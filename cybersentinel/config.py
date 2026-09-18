"""
CyberSentinel v3 — configuration & taxonomy.

This file defines the DETECTION taxonomy the model learns to recognise:
MITRE ATT&CK techniques, high-level attack classes, malware families,
the kill-chain stage ordering, and the behavioural feature schema that a
defensive sensor (EDR / sandbox / honeypot) would emit.

Nothing here is executable attack code. Every "signal" below is an
*observation* the classifier consumes as input — e.g. "shadow copies were
deleted" is a feature the detector reads, not an action it performs.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# MITRE ATT&CK techniques the model can predict (expanded from the original 8)
# id -> (short name, tactic)
# ---------------------------------------------------------------------------
TECHNIQUES: dict[str, tuple[str, str]] = {
    # Reconnaissance / Discovery
    "T1016": ("System Network Config Discovery", "discovery"),
    "T1057": ("Process Discovery", "discovery"),
    "T1082": ("System Information Discovery", "discovery"),
    "T1083": ("File and Directory Discovery", "discovery"),
    "T1087": ("Account Discovery", "discovery"),
    "T1135": ("Network Share Discovery", "discovery"),
    # Initial Access
    "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1566": ("Phishing", "initial-access"),
    "T1133": ("External Remote Services", "initial-access"),
    "T1110": ("Brute Force", "credential-access"),
    # Execution
    "T1059": ("Command and Scripting Interpreter", "execution"),
    "T1047": ("Windows Management Instrumentation", "execution"),
    "T1053": ("Scheduled Task/Job", "execution"),
    "T1204": ("User Execution", "execution"),
    # Persistence
    "T1547": ("Boot or Logon Autostart Execution", "persistence"),
    "T1543": ("Create or Modify System Process", "persistence"),
    "T1136": ("Create Account", "persistence"),
    # Privilege Escalation
    "T1548": ("Abuse Elevation Control Mechanism", "privilege-escalation"),
    "T1055": ("Process Injection", "privilege-escalation"),
    "T1068": ("Exploitation for Privilege Escalation", "privilege-escalation"),
    # Defense Evasion
    "T1562": ("Impair Defenses", "defense-evasion"),
    "T1070": ("Indicator Removal", "defense-evasion"),
    "T1027": ("Obfuscated Files or Information", "defense-evasion"),
    "T1620": ("Reflective Code Loading", "defense-evasion"),
    # Credential Access
    "T1003": ("OS Credential Dumping", "credential-access"),
    "T1555": ("Credentials from Password Stores", "credential-access"),
    # Lateral Movement
    "T1021": ("Remote Services", "lateral-movement"),
    "T1550": ("Use Alternate Authentication Material", "lateral-movement"),
    "T1570": ("Lateral Tool Transfer", "lateral-movement"),
    "T1105": ("Ingress Tool Transfer", "command-and-control"),
    # Command & Control
    "T1071": ("Application Layer Protocol", "command-and-control"),
    "T1090": ("Proxy", "command-and-control"),
    "T1573": ("Encrypted Channel", "command-and-control"),
    # Exfiltration
    "T1041": ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1048": ("Exfiltration Over Alternative Protocol", "exfiltration"),
    "T1567": ("Exfiltration Over Web Service", "exfiltration"),
    # Impact
    "T1486": ("Data Encrypted for Impact", "impact"),
    "T1490": ("Inhibit System Recovery", "impact"),
    "T1489": ("Service Stop", "impact"),
    "T1496": ("Resource Hijacking", "impact"),
    "T1561": ("Disk Wipe", "impact"),
}

TECHNIQUE_IDS: list[str] = list(TECHNIQUES.keys())

# MITRE tactics (kill-chain phases), ordered roughly by progression.
TACTICS: list[str] = [
    "reconnaissance", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "command-and-control",
    "exfiltration", "impact",
]

# ---------------------------------------------------------------------------
# High-level attack classes (session-level label)
# ---------------------------------------------------------------------------
ATTACK_CLASSES: list[str] = [
    "benign",
    "ransomware",
    "wiper",
    "rat",
    "infostealer",
    "botnet",
    "cryptominer",
    "apt",
    "fileless",
]

# Representative malware families per class (family-level label).
MALWARE_FAMILIES: dict[str, list[str]] = {
    "benign":      ["n/a"],
    "ransomware":  ["LockBit", "BlackCat", "Cl0p", "Conti", "Ryuk"],
    "wiper":       ["NotPetya", "HermeticWiper", "CaddyWiper"],
    "rat":         ["AsyncRAT", "QuasarRAT", "Remcos"],
    "infostealer": ["RedLine", "Vidar", "LummaC2"],
    "botnet":      ["Emotet", "TrickBot", "Qakbot", "Mirai"],
    "cryptominer": ["XMRig", "LemonDuck"],
    "apt":         ["Lazarus", "APT28", "APT41"],
    "fileless":    ["CobaltStrike", "Meterpreter", "SliverC2"],
}
FAMILY_IDS: list[str] = sorted({f for fs in MALWARE_FAMILIES.values() for f in fs})

# ---------------------------------------------------------------------------
# Kill-chain templates: for each attack class, an ordered list of "stages",
# each stage being a pool of techniques the campaign draws from. The synthetic
# generator walks these templates to produce realistic technique ORDERINGS.
# These are behavioural sequence priors, not payloads.
# ---------------------------------------------------------------------------
KILL_CHAIN_TEMPLATES: dict[str, list[list[str]]] = {
    "benign": [
        ["T1082", "T1057", "T1016"],
        ["T1083", "T1087"],
    ],
    "ransomware": [
        ["T1566", "T1190", "T1133"],           # initial access
        ["T1059", "T1204", "T1047"],           # execution
        ["T1547", "T1053"],                    # persistence
        ["T1548", "T1055"],                    # priv-esc
        ["T1562", "T1070", "T1490"],           # evasion + recovery inhibit
        ["T1083", "T1135", "T1082"],           # discovery
        ["T1021", "T1550", "T1570"],           # lateral movement
        ["T1486", "T1489"],                    # impact (encrypt)
    ],
    "wiper": [
        ["T1190", "T1566"],
        ["T1059", "T1047"],
        ["T1562", "T1070"],
        ["T1082", "T1083"],
        ["T1561", "T1489"],                    # disk wipe / service stop
    ],
    "rat": [
        ["T1566", "T1204"],
        ["T1059", "T1055"],
        ["T1547", "T1543"],
        ["T1071", "T1573", "T1105"],           # C2 beaconing
        ["T1003", "T1555"],                    # credential theft
    ],
    "infostealer": [
        ["T1566", "T1204"],
        ["T1059"],
        ["T1555", "T1003"],                    # steal creds / wallets
        ["T1027"],
        ["T1041", "T1567"],                    # exfil
    ],
    "botnet": [
        ["T1190", "T1110"],
        ["T1059", "T1105"],
        ["T1547", "T1053"],
        ["T1071", "T1090"],                    # C2
        ["T1496"],                             # resource hijack / DDoS role
    ],
    "cryptominer": [
        ["T1190", "T1133"],
        ["T1059"],
        ["T1053", "T1543"],
        ["T1496"],                             # resource hijacking
    ],
    "apt": [
        ["T1566", "T1190", "T1133"],
        ["T1059", "T1047", "T1620"],           # LOLBins / reflective load
        ["T1547", "T1543", "T1136"],
        ["T1068", "T1055"],
        ["T1562", "T1070", "T1027"],
        ["T1003", "T1555"],
        ["T1021", "T1550", "T1570"],
        ["T1041", "T1048"],                    # slow exfil
    ],
    "fileless": [
        ["T1204", "T1566"],
        ["T1059", "T1620", "T1055"],           # memory-only execution
        ["T1047"],
        ["T1071", "T1573"],
        ["T1003"],
    ],
}

# Per-class base severity (0..1) used to synthesise the severity regression
# target. Higher = more damaging on success.
CLASS_SEVERITY: dict[str, float] = {
    "benign": 0.05, "ransomware": 0.97, "wiper": 0.99, "rat": 0.70,
    "infostealer": 0.65, "botnet": 0.55, "cryptominer": 0.40,
    "apt": 0.90, "fileless": 0.75,
}

# ---------------------------------------------------------------------------
# Behavioural feature schema (per event). These are SENSOR OBSERVATIONS.
# ---------------------------------------------------------------------------
# Numeric features (continuous / count) — normalised before training.
NUMERIC_FEATURES: list[str] = [
    "dst_port",
    "bytes_sent",
    "connection_count",
    "time_delta_secs",
    "hour_of_day",
    "session_position",       # 0..1 how far into the session
    "failed_auth_attempts",
    "command_length",
    "files_touched_rate",     # files/sec — encryption prep signal
    "files_encrypted_count",
    "data_exfil_mb",
    "cpu_load_pct",           # cryptominer signal
    "beacon_interval_secs",   # C2 regularity
    "remote_hosts_targeted",  # lateral movement scope
]

# Boolean flags (0/1) — behavioural indicators.
BOOLEAN_FEATURES: list[str] = [
    "parent_child_anomaly",   # e.g. winword.exe -> powershell.exe
    "lolbin_used",            # certutil / regsvr32 / mshta ...
    "process_injection",      # T1055 observed
    "memory_only",            # fileless
    "shadow_copies_deleted",  # T1490 — strong ransomware signal
    "security_tool_disabled", # T1562
    "event_logs_cleared",     # T1070
    "lsass_access",           # T1003.001
    "smb_spread",             # worm-like lateral movement
    "tor_or_proxy",           # T1090
]

PROTOCOLS: list[str] = ["none", "tcp", "udp", "http", "https", "dns", "icmp", "smb"]

# ---------------------------------------------------------------------------
# Model / training hyperparameters (modest defaults so it runs on CPU).
# ---------------------------------------------------------------------------
class HP:
    max_seq_len = 16
    technique_emb = 64
    tactic_emb = 16
    protocol_emb = 8
    numeric_proj = 32
    boolean_proj = 16
    lstm_hidden = 128
    lstm_layers = 2
    bidirectional = True
    attn_heads = 8
    dropout = 0.3
    label_smoothing = 0.1

    lr = 1e-3
    weight_decay = 1e-5
    batch_size = 64
    epochs = 15

    # multi-task loss weights
    w_technique = 0.45
    w_class = 0.25
    w_family = 0.15
    w_severity = 0.15


# Derived sizes (imported elsewhere)
NUM_TECHNIQUES = len(TECHNIQUE_IDS)
NUM_TACTICS = len(TACTICS)
NUM_PROTOCOLS = len(PROTOCOLS)
NUM_ATTACK_CLASSES = len(ATTACK_CLASSES)
NUM_FAMILIES = len(FAMILY_IDS)
NUM_NUMERIC = len(NUMERIC_FEATURES)
NUM_BOOLEAN = len(BOOLEAN_FEATURES)
