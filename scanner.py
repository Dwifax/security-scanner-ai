#!/usr/bin/env python3
"""AI Security Scanner - OWASP Top 10 vulnerability detection."""
import re, json, sys
from pathlib import Path
from datetime import datetime

RULES = [
    # A01: Broken Access Control
    ("A01", "CRITICAL", "File serving from user path", r"send_file\(.*request"),
    ("A01", "CRITICAL", "Path traversal", r"os.path.join.*request\.(args|form|json)"),
    # A02: Cryptographic Failures
    ("A02", "HIGH", "MD5 usage (weak)", r"(?i)md5\s*\("),
    ("A02", "HIGH", "SSL verification disabled", r"(?i)verify\s*=\s*False"),
    ("A02", "CRITICAL", "Weak secret key", r"(?i)SECRET_KEY\s*=\s*["'][^"']{1,16}["']"),
    # A03: Injection
    ("A03", "CRITICAL", "SQL injection via f-string", r"(?i)execute\s*\(.*f["'].*\{"),
    ("A03", "CRITICAL", "Code injection via eval", r"(?i)eval\s*\(.*request"),
    ("A03", "CRITICAL", "Command injection", r"(?i)subprocess.call.*shell\s*=\s*True"),
    ("A03", "CRITICAL", "Code injection via exec", r"(?i)exec\s*\(.*request"),
    ("A03", "HIGH", "Command injection (os.system)", r"(?i)os\.system\s*\(.*request"),
    # A04: Insecure Design
    ("A04", "LOW", "Bare except", r"except\s*:"),
    # A05: Security Misconfiguration
    ("A05", "HIGH", "Debug mode enabled", r"(?i)DEBUG\s*=\s*True"),
    ("A05", "HIGH", "Permissive CORS", r"(?i)Access-Control-Allow-Origin.*\*"),
    ("A05", "CRITICAL", "Default password", r"(?i)password\s*=\s*["'](?:admin|root|password|123)"),
    # A06: Vulnerable Components
    ("A06", "MEDIUM", "Outdated Flask", r"(?i)flask[<>=]+0\."),
    # A07: Auth Failures
    ("A07", "CRITICAL", "JWT without verification", r"(?i)jwt\.decode.*verify\s*=\s*False"),
    ("A07", "HIGH", "Password in request comparison", r"(?i)password.*==.*request"),
    # A08: Data Integrity
    ("A08", "CRITICAL", "Insecure deserialization (pickle)", r"(?i)pickle.loads?\s*\("),
    ("A08", "HIGH", "Unsafe YAML loading", r"(?i)yaml.load\s*\((?!.*Loader)"),
    # A09: Logging
    ("A09", "HIGH", "Sensitive data in logs", r"(?i)print\(.*password|print\(.*secret"),
    # A10: SSRF
    ("A10", "CRITICAL", "SSRF via user URL", r"(?i)requests.get\(.*request"),
]

def scan_file(filepath):
    try:
        lines = filepath.read_text(errors="ignore").split("\n")
    except:
        return []
    findings = []
    for cat, sev, title, pattern in RULES:
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line):
                findings.append({"file": str(filepath), "line": i, "cat": cat, "severity": sev, "title": title, "code": line.strip()[:120]})
    return findings

def scan_dir(path):
    exts = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".rs"}
    all_f = []; count = 0
    for ext in exts:
        for f in Path(path).rglob(f"*{ext}"):
            if ".git" in str(f) or "node_modules" in str(f): continue
            count += 1
            all_f.extend(scan_file(f))
    return count, all_f

def report(files, findings):
    crit = sum(1 for f in findings if f["severity"]=="CRITICAL")
    high = sum(1 for f in findings if f["severity"]=="HIGH")
    med = sum(1 for f in findings if f["severity"]=="MEDIUM")
    low = sum(1 for f in findings if f["severity"]=="LOW")
    score = max(0, 100 - crit*20 - high*10 - med*4 - low)
    grade = "A" if score>=90 else "B" if score>=70 else "C" if score>=50 else "F"

    print(f"\n{'='*60}")
    print(f"  AI SECURITY SCANNER - OWASP Top 10 Analysis")
    print(f"{'='*60}")
    print(f"  Date: {datetime.now():%Y-%m-%d %H:%M}")
    print(f"  Files: {files} | Score: {score}/100 (Grade: {grade})")
    print(f"  CRITICAL: {crit} | HIGH: {high} | MEDIUM: {med} | LOW: {low}")
    print(f"{'='*60}")

    by_cat = {}
    for f in findings:
        by_cat.setdefault(f["cat"], []).append(f)
    for cat in sorted(by_cat):
        fs = by_cat[cat]
        print(f"\n  [OWASP-{cat}]")
        for f in fs[:5]:
            icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵"}[f["severity"]]
            print(f"    {icon} {f['title']} ({f['severity']})")
            print(f"       {f['file']}:{f['line']}")
            print(f"       {f['code'][:100]}")
        if len(fs) > 5:
            print(f"    ... and {len(fs)-5} more")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"Scanning {path} for OWASP Top 10 vulnerabilities...")
    files, findings = scan_dir(path)
    report(files, findings)
