import re

# SQLi patterns
SQLI_PATTERNS = [
    r"(?i)(\bOR\b|\bAND\b)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+",
    r"(?i)(UNION\s+SELECT|UNION\s+ALL\s+SELECT)",
    r"(?i)(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)",
    r"(?i)(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)",
    r"(?i)(EXEC\s*\(|EXECUTE\s*\(|xp_cmdshell)",
    r"(?i)(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)",
    r"--\s*$",
    r"#\s*$",
    r"(?i)\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1",
    r"(?i)(;|\bGO\b)\s*(DROP|DELETE|UPDATE|INSERT)",
    r"(?i)(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)",
    r"(?i)(INFORMATION_SCHEMA|SYS\.TABLES|PG_TABLES)",
]

# XSS patterns
XSS_PATTERNS = [
    r"(?i)<script[\s>]",
    r"(?i)</script>",
    r"(?i)javascript\s*:",
    r"(?i)on(load|error|click|mouseover|focus|blur|change|submit)\s*=",
    r"(?i)<iframe[\s>]",
    r"(?i)<img[^>]+src\s*=\s*['\"]?javascript",
    r"(?i)alert\s*\(",
    r"(?i)document\.(cookie|write|location)",
    r"(?i)eval\s*\(",
    r"(?i)<svg[^>]+on\w+\s*=",
    r"(?i)expression\s*\(",
    r"(?i)vbscript\s*:",
]

# Directory traversal
TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"(?i)(etc/passwd|etc/shadow|windows/system32|boot\.ini)",
    r"(?i)(%2e%2e|%252e%252e)",
]

# Port scan indicators (many ports in short time — handled at profile level)
PORT_SCAN_PATHS = [
    "/admin", "/phpmyadmin", "/.env", "/wp-admin",
    "/wp-login.php", "/manager/html", "/actuator", "/console",
    "/backup", "/config", "/.git", "/robots.txt",
]


def classify_attack(payload: str = "", path: str = "", service: str = "Web") -> tuple[str, str]:
    """
    Returns (attack_type, severity).
    """
    if service == "SSH":
        return "SSH Brute Force", "High"

    if service == "FTP":
        return "FTP Unauthorized", "Medium"

    if service == "Database":
        return "DB Probe", "High"

    text = f"{payload} {path}".strip()

    # Check SQLi
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, text):
            return "SQL Injection", "High"

    # Check XSS
    for pattern in XSS_PATTERNS:
        if re.search(pattern, text):
            return "XSS", "High"

    # Check Directory Traversal
    for pattern in TRAVERSAL_PATTERNS:
        if re.search(pattern, text):
            return "Directory Traversal", "Medium"

    # Check port-scan-style recon paths
    for scan_path in PORT_SCAN_PATHS:
        if scan_path.lower() in path.lower():
            return "Port Scan", "Low"

    return "Other", "Low"


def severity_from_attack_type(attack_type: str) -> str:
    mapping = {
        "SQL Injection":      "High",
        "XSS":                "High",
        "SSH Brute Force":    "High",
        "FTP Unauthorized":   "Medium",
        "DB Probe":           "High",
        "Directory Traversal":"Medium",
        "Port Scan":          "Low",
        "Other":              "Low",
    }
    return mapping.get(attack_type, "Low")
