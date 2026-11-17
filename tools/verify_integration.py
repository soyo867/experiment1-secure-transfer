"""Run independent real-TLS acceptance tests and write machine-readable evidence."""
import io
import json
from pathlib import Path
import platform
import sys
import time
import unittest

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(BASE))


def main():
    output = BASE/"evidence"
    output.mkdir(exist_ok=True)
    suite = unittest.defaultTestLoader.discover(str(BASE/"tests"),pattern="test_integration.py")
    buffer = io.StringIO()
    before = time.perf_counter()
    result = unittest.TextTestRunner(stream=buffer,verbosity=2).run(suite)
    elapsed = time.perf_counter()-before
    (output/"integration_tests.txt").write_text(buffer.getvalue(),encoding="utf-8")
    test_module = sys.modules.get("test_integration")
    metrics = getattr(getattr(test_module,"IntegrationTests",None),"metrics",{})
    evidence = {"result":"PASS" if result.wasSuccessful() else "FAIL","tests":result.testsRun,"failures":len(result.failures),
                "errors":len(result.errors),"skipped":[{"test":str(t),"reason":reason} for t,reason in result.skipped],
                "seconds":round(elapsed,3),"python":platform.python_version(),"platform":platform.platform(),
                "transport":"Actual localhost TLS sockets with freshly generated CA and pinned client identities", "metrics":metrics}
    (output/"integration_tests.json").write_text(json.dumps(evidence,ensure_ascii=False,indent=2),encoding="utf-8")
    print(buffer.getvalue())
    print(json.dumps(evidence,ensure_ascii=False,indent=2))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    if hasattr(sys.stdout,"reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
