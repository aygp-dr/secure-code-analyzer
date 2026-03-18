"""Clean Python code with no security vulnerabilities — used as negative test."""
import hashlib
import os


def get_config():
    """Read configuration from environment."""
    return os.environ.get("APP_CONFIG", "{}")


def compute_hash(data):
    """Compute SHA-256 hash of input data."""
    return hashlib.sha256(data.encode()).hexdigest()


def add_numbers(a, b):
    """Simple arithmetic — no security concerns."""
    return a + b
