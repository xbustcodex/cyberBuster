"""Seed fleet + CVE + release data so the dashboard is meaningful on first load."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import random
import uuid


def _now(offset_min: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_min)).isoformat()


def _iso_days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


DEFAULT_TOOLS_BY_PROFILE = {
    "offense": [
        ("nmap", "7.95"), ("burpsuite", "2025.11.2"), ("ffuf", "2.1.0"),
        ("sqlmap", "1.8.10"), ("impacket", "0.12.0"), ("bloodhound", "5.0.4"),
        ("netexec", "1.3.0"), ("sliver", "1.5.42"), ("metasploit", "6.4.30"),
        ("ghidra", "11.2.1"), ("radare2", "5.9.4"), ("evil-winrm", "3.7"),
    ],
    "defense": [
        ("volatility3", "2.7.0"), ("yara", "4.5.2"), ("zeek", "6.0.6"),
        ("suricata", "7.0.7"), ("wazuh-agent", "4.9.1"), ("velociraptor", "0.73.2"),
        ("osquery", "5.14.1"), ("autopsy", "4.21.0"), ("plaso", "20240826"),
        ("chainsaw", "2.10.1"), ("hayabusa", "2.19.0"),
    ],
    "analyst": [
        ("wireshark", "4.4.2"), ("tcpdump", "4.99.5"), ("mitmproxy", "11.0.2"),
        ("vscode", "1.95.3"), ("docker", "27.4.0"), ("qemu", "9.1.2"),
        ("git", "2.47.1"), ("age", "1.2.0"), ("sops", "3.9.2"),
    ],
}

HOSTNAMES = [
    ("cerberus-01", "nixos"), ("cerberus-02", "nixos"), ("hydra-red-01", "nixos"),
    ("hydra-red-02", "nixos"), ("chimera-blue-01", "nixos"), ("chimera-blue-02", "windows"),
    ("phoenix-analyst-01", "nixos"), ("phoenix-analyst-02", "windows"),
    ("sphinx-dfir-01", "nixos"), ("griffin-osint-01", "windows"),
    ("basilisk-recon-01", "nixos"), ("kraken-mal-01", "windows"),
]

RELEASES = [
    ("v0.9.0", "stable", 30, "Initial GA. Nix flake profile engine + 30 essential tools.", "release-bot"),
    ("v0.9.1", "stable", 22, "Patched: nmap 7.95 pin, wazuh-agent 4.9.1 upgrade.", "release-bot"),
    ("v0.10.0", "beta", 14, "Windows DSC parity for defense profile (72% coverage).", "atlas"),
    ("v0.10.1", "beta", 7, "Signed release pipeline (cosign) + reproducibility check.", "atlas"),
    ("v0.11.0-rc1", "nightly", 2, "CVE feed integration (NVD). Fleet enrollment CLI.", "release-bot"),
]

CVE_SEEDS = [
    ("CVE-2024-45782", "critical", 9.8, "curl", ["8.4.0", "8.5.0"], "Heap buffer overflow in curl <= 8.5.0.", "sec-master patch --cve CVE-2024-45782"),
    ("CVE-2024-43532", "high", 8.8, "wireshark", ["4.4.1", "4.4.2"], "Wireshark dissector RCE via crafted RTP packet.", "sec-master patch --cve CVE-2024-43532"),
    ("CVE-2025-11201", "high", 7.8, "docker", ["27.3.0", "27.4.0"], "Docker daemon privilege escalation via mount race.", "sec-master patch --cve CVE-2025-11201"),
    ("CVE-2024-56789", "medium", 6.5, "git", ["2.47.0", "2.47.1"], "Git clone path traversal on Windows checkouts.", "sec-master patch --cve CVE-2024-56789"),
    ("CVE-2024-11111", "medium", 5.9, "metasploit", ["6.4.29", "6.4.30"], "Metasploit meterpreter memory leak DoS.", "sec-master patch --cve CVE-2024-11111"),
    ("CVE-2025-00042", "low", 3.7, "yara", ["4.5.1", "4.5.2"], "YARA regex compilation ReDoS.", "sec-master patch --cve CVE-2025-00042"),
    ("CVE-2025-32101", "critical", 9.1, "sliver", ["1.5.41", "1.5.42"], "Sliver C2 unauthenticated command exec.", "sec-master patch --cve CVE-2025-32101"),
    ("CVE-2025-19844", "high", 8.1, "suricata", ["7.0.6", "7.0.7"], "Suricata HTTP2 parser memory corruption.", "sec-master patch --cve CVE-2025-19844"),
]


def _flake_hash() -> str:
    return "sha256-" + uuid.uuid4().hex[:22]


def _dsc_hash() -> str:
    return "SHA256:" + uuid.uuid4().hex[:20].upper()


def build_workstations() -> list[dict]:
    random.seed(7)
    out = []
    profiles = ["offense", "defense", "analyst"]
    statuses = ["online", "online", "online", "drift", "offline"]
    for i, (host, os_kind) in enumerate(HOSTNAMES):
        prof = profiles[i % 3]
        tools = [{"name": n, "version": v} for n, v in DEFAULT_TOOLS_BY_PROFILE[prof]]
        # Sprinkle a few analyst tools everywhere
        tools += [{"name": n, "version": v} for n, v in DEFAULT_TOOLS_BY_PROFILE["analyst"][:3]]
        out.append({
            "id": str(uuid.uuid4()),
            "hostname": host,
            "os": os_kind,
            "profile": prof,
            "agent_version": random.choice(["0.9.1", "0.10.0", "0.10.1"]),
            "flake_hash": _flake_hash() if os_kind == "nixos" else None,
            "dsc_hash": _dsc_hash() if os_kind == "windows" else None,
            "tools": tools,
            "tags": [prof, os_kind, random.choice(["prod", "lab", "field"])],
            "enrolled_at": _iso_days_ago(random.randint(5, 90)),
            "last_heartbeat": _iso_days_ago(0) if statuses[i % 5] != "offline" else _iso_days_ago(random.randint(2, 14)),
            "status": statuses[i % 5],
            "ip_address": f"10.13.{random.randint(1,254)}.{random.randint(1,254)}",
        })
    return out


def build_releases() -> list[dict]:
    return [
        {
            "id": str(uuid.uuid4()),
            "version": v,
            "commit_sha": uuid.uuid4().hex[:40],
            "signature_status": "valid",
            "signer": signer,
            "published_at": _iso_days_ago(days_ago),
            "changelog": changelog,
            "channel": channel,
        }
        for v, channel, days_ago, changelog, signer in RELEASES
    ]


def build_cves(workstations: list[dict]) -> list[dict]:
    out = []
    for cve_id, sev, cvss, tool, versions, summary, remediation in CVE_SEEDS:
        matched = 0
        for ws in workstations:
            for t in ws["tools"]:
                if t["name"] == tool and t["version"] in versions:
                    matched += 1
                    break
        out.append({
            "id": str(uuid.uuid4()),
            "cve_id": cve_id,
            "severity": sev,
            "cvss": cvss,
            "published": _iso_days_ago(random.randint(1, 40)),
            "summary": summary,
            "affected_tool": tool,
            "affected_versions": versions,
            "remediation": remediation,
            "matched_workstations": matched,
        })
    return out


def build_audit(workstations: list[dict]) -> list[dict]:
    events = []
    kinds = [
        ("enroll", "Workstation enrolled via one-time token"),
        ("heartbeat", "Agent heartbeat received"),
        ("profile_switch", "Switched profile (bootloader specialisation)"),
        ("cve_match", "CVE matched against installed tool"),
        ("tool_update", "Tooling layer updated (nix flake update)"),
    ]
    for ws in workstations:
        for i in range(random.randint(2, 5)):
            k, msg = random.choice(kinds)
            events.append({
                "id": str(uuid.uuid4()),
                "workstation_id": ws["id"],
                "hostname": ws["hostname"],
                "kind": k,
                "message": msg,
                "at": _iso_days_ago(random.randint(0, 20)),
                "meta": {},
            })
    return events
