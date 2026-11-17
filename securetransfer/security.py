"""File confinement, strict identifiers, and identity-wide resource controls."""
import hashlib
import os
from pathlib import Path
import re
import stat
import threading
import time
import unicodedata


class OperationError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def integer(value, name, minimum=0, maximum=(1 << 63)-1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise OperationError("INVALID_ARGUMENT", f"{name} must be an integer in {minimum}..{maximum}")
    return value


def file_name(value):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 180:
        raise OperationError("BAD_PATH", "Filename must contain 1..180 UTF-8 bytes")
    if value != unicodedata.normalize("NFC", value):
        raise OperationError("BAD_PATH", "Filename must use NFC Unicode normalization")
    if value.startswith(".") or value.endswith((".", " ")) or ".." in value:
        raise OperationError("BAD_PATH", "Hidden, dot and traversal names are forbidden")
    if re.search(r'[<>:"/\\|?*\x00-\x1f\x7f]', value) or any(unicodedata.category(c).startswith("C") for c in value):
        raise OperationError("BAD_PATH", "Filename contains a forbidden character")
    if value.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(10)], *[f"LPT{i}" for i in range(10)]}:
        raise OperationError("BAD_PATH", "Windows reserved filename")
    return value


def digest(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise OperationError("INVALID_ARGUMENT", "sha256 must be lowercase hexadecimal")
    return value


def no_link(path):
    path = Path(path)
    if path.is_symlink():
        raise OperationError("BAD_PATH", "Symbolic links are forbidden")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        raise OperationError("BAD_PATH", "Windows reparse points are forbidden")


def confined(root, name):
    root = Path(root)
    no_link(root)
    name = file_name(name)
    target = root/name
    no_link(target)
    if target.parent.resolve() != root.resolve():
        raise OperationError("BAD_PATH", "File outside assigned root")
    return target


def secure_open(path, flags, mode=0o600):
    no_link(path)
    descriptor = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), mode)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise OperationError("BAD_PATH", "Only regular files are supported")
    return descriptor


def sha256_file(path, limit=None):
    hasher = hashlib.sha256()
    with os.fdopen(secure_open(path, os.O_RDONLY), "rb") as handle:
        remaining = limit
        while remaining is None or remaining > 0:
            block = handle.read(65536 if remaining is None else min(65536, remaining))
            if not block:
                break
            hasher.update(block)
            if remaining is not None:
                remaining -= len(block)
    return hasher.hexdigest()


class RateLimiter:
    def __init__(self, rate, capacity):
        self.rate, self.capacity = float(rate), float(capacity)
        self.tokens, self.updated = float(capacity), time.monotonic()
        self.lock = threading.Lock()

    def allow(self, amount=1):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now-self.updated)*self.rate)
            self.updated = now
            if self.tokens < amount:
                return False
            self.tokens -= amount
            return True


class BandwidthLimiter:
    """A single identity's upload + download budget shared across connections.

    Reserving a finish time implements a leaky bucket with no per-connection
    rate multiplier. Waiting happens outside the lock and is interruptible.
    """
    def __init__(self, bytes_per_second):
        self.rate = int(bytes_per_second)
        self.next_time = time.monotonic()
        self.lock = threading.Lock()

    def consume(self, count, stop):
        if count == 0:
            return
        with self.lock:
            now = time.monotonic()
            self.next_time = max(now, self.next_time) + count/self.rate
            delay = self.next_time-now
        if stop.wait(delay):
            raise ConnectionAbortedError("Server is stopping")
