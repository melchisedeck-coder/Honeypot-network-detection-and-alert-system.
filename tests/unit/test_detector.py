import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from honeypot.engine.detector import classify_attack


class TestSQLiDetection:
    def test_or_1_equals_1(self):
        attack, sev = classify_attack(payload="' OR '1'='1")
        assert attack == "SQL Injection"
        assert sev == "High"

    def test_union_select(self):
        attack, _ = classify_attack(payload="UNION SELECT * FROM users")
        assert attack == "SQL Injection"

    def test_drop_table(self):
        attack, _ = classify_attack(payload="DROP TABLE students")
        assert attack == "SQL Injection"

    def test_information_schema(self):
        attack, _ = classify_attack(payload="SELECT * FROM INFORMATION_SCHEMA.TABLES")
        assert attack == "SQL Injection"


class TestXSSDetection:
    def test_script_tag(self):
        attack, sev = classify_attack(payload="<script>alert(1)</script>")
        assert attack == "XSS"
        assert sev == "High"

    def test_onerror_handler(self):
        attack, _ = classify_attack(payload="<img onerror=alert(1)>")
        assert attack == "XSS"

    def test_javascript_protocol(self):
        attack, _ = classify_attack(payload="javascript:alert(document.cookie)")
        assert attack == "XSS"


class TestDirectoryTraversal:
    def test_dot_dot_slash(self):
        attack, _ = classify_attack(path="/../../../etc/passwd")
        assert attack == "Directory Traversal"

    def test_etc_passwd(self):
        attack, _ = classify_attack(path="/etc/passwd")
        assert attack == "Directory Traversal"


class TestServiceDetection:
    def test_ssh_brute_force(self):
        attack, sev = classify_attack(service="SSH")
        assert attack == "SSH Brute Force"
        assert sev == "High"

    def test_ftp_unauthorized(self):
        attack, sev = classify_attack(service="FTP")
        assert attack == "FTP Unauthorized"
        assert sev == "Medium"

    def test_db_probe(self):
        attack, sev = classify_attack(service="Database")
        assert attack == "DB Probe"
        assert sev == "High"


class TestPortScanDetection:
    def test_admin_path(self):
        attack, _ = classify_attack(path="/admin")
        assert attack == "Port Scan"

    def test_phpmyadmin(self):
        attack, _ = classify_attack(path="/phpmyadmin")
        assert attack == "Port Scan"

    def test_env_file(self):
        attack, _ = classify_attack(path="/.env")
        assert attack == "Port Scan"


class TestBenignRequest:
    def test_normal_homepage(self):
        attack, sev = classify_attack(payload="", path="/", service="Web")
        assert attack == "Other"
        assert sev == "Low"
