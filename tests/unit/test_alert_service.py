import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from honeypot.engine.detector import severity_from_attack_type


class TestSeverityMapping:
    def test_sqli_is_high(self):
        assert severity_from_attack_type("SQL Injection") == "High"

    def test_xss_is_high(self):
        assert severity_from_attack_type("XSS") == "High"

    def test_ssh_is_high(self):
        assert severity_from_attack_type("SSH Brute Force") == "High"

    def test_ftp_is_medium(self):
        assert severity_from_attack_type("FTP Unauthorized") == "Medium"

    def test_port_scan_is_low(self):
        assert severity_from_attack_type("Port Scan") == "Low"

    def test_db_probe_is_high(self):
        assert severity_from_attack_type("DB Probe") == "High"

    def test_unknown_defaults_to_low(self):
        assert severity_from_attack_type("Unknown Attack") == "Low"


class TestRiskScore:
    def _make_profile(self, attempts, high, critical):
        class MockProfile:
            total_attempts = attempts
            high_severity_count = high
            critical_severity_count = critical

            def compute_risk_score(self):
                volume  = min(self.total_attempts / 100, 1.0) * 3.0
                hs      = self.high_severity_count + self.critical_severity_count
                sev_rate = hs / max(self.total_attempts, 1)
                severity = min(sev_rate, 1.0) * 7.0
                return round(volume + severity, 2)

        return MockProfile()

    def test_zero_attempts_gives_zero_score(self):
        p = self._make_profile(0, 0, 0)
        assert p.compute_risk_score() == 0.0

    def test_all_high_severity_maximizes_score(self):
        p = self._make_profile(100, 100, 0)
        score = p.compute_risk_score()
        assert score >= 9.0

    def test_low_volume_low_severity_gives_low_score(self):
        p = self._make_profile(2, 0, 0)
        assert p.compute_risk_score() < 1.0
