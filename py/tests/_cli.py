"""Helpers that run the verifier the way a vendor does: python -I <file> <command>."""
import subprocess
import sys

from ._paths import VERIFIER


def run_cli(args, stdin=b"", cwd=None, timeout=60):
    proc = subprocess.run([sys.executable, "-I", str(VERIFIER), *args], input=stdin, capture_output=True, cwd=cwd, timeout=timeout)
    return proc.returncode, proc.stdout, proc.stderr
