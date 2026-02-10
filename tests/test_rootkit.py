import unittest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from rootkit.core import RootkitDetector
from rootkit.persistence import PersistenceAnalyzer
from rootkit.stealth import StealthAnalyzer

class TestDetector(unittest.TestCase):
    def test_scan(self):
        d = RootkitDetector()
        d.full_scan()
        report = d.report()
        self.assertIn("total", report)
        self.assertIn("findings", report)

class TestPersistence(unittest.TestCase):
    def test_analyze(self):
        p = PersistenceAnalyzer()
        results = p.analyze_all()
        self.assertIn("cron_system", results)

class TestStealth(unittest.TestCase):
    def test_proc(self):
        result = StealthAnalyzer.check_proc_hiding()
        self.assertIn("proc_entries", result)

if __name__ == "__main__":
    unittest.main()
