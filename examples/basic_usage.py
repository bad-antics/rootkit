#!/usr/bin/env python3
"""Rootkit Detection Scanner"""
from rootkit.core import RootkitDetector

detector = RootkitDetector()
findings = detector.full_scan()
report = detector.report()

print(f"Scan complete: {report['total']} findings")
print(f"  Critical: {report['critical']}")
print(f"  High: {report['high']}")
for f in report["findings"]:
    print(f"  [{f.get('severity','?')}] {f['type']}: {json.dumps({k:v for k,v in f.items() if k not in ('type','severity')})}")
