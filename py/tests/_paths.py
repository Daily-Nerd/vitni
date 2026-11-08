"""Where things live, resolved once. Importing this module also puts py/ on
sys.path so `import vitni_verify` works however the tests are launched."""
import pathlib
import sys

TESTS_DIR = pathlib.Path(__file__).resolve().parent
PY_DIR = TESTS_DIR.parent
ROOT = PY_DIR.parent
VECTORS = ROOT / "conformance" / "vectors"
WYCHEPROOF = ROOT / "conformance" / "third_party" / "wycheproof"
VERIFIER = PY_DIR / "vitni_verify.py"

if str(PY_DIR) not in sys.path:
    sys.path.insert(0, str(PY_DIR))
