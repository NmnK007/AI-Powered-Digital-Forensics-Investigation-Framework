"""
Evidence Store for SutraTrace.
Handles cryptographic hashing, immutable original storage, working copies,
and live integrity verification (SHA-256).
"""

import hashlib
import os
import shutil
import stat
from pathlib import Path
from typing import Tuple, Optional, Dict, Any

VAULT_DIR = Path("C:/Users/P C/.gemini/antigravity/scratch/sutratrace/sutratrace/evidence_vault")
ORIGINALS_DIR = VAULT_DIR / "originals"
WORKING_DIR = VAULT_DIR / "working_copies"


def ensure_vault_directories():
    ORIGINALS_DIR.mkdir(parents=True, exist_ok=True)
    WORKING_DIR.mkdir(parents=True, exist_ok=True)


def calculate_sha256_bytes(data: bytes) -> str:
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def calculate_sha256_file(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def store_evidence_file(case_id: str, evidence_id: str, filename: str, content: bytes) -> Tuple[str, str, int]:
    """
    Stores evidence file:
    1. Computes SHA-256 immediately upon ingestion.
    2. Writes to immutable originals store.
    3. Marks original as read-only.
    4. Writes a working copy for parsers and analysis.
    Returns: (sha256_hash, relative_storage_path, size_bytes)
    """
    ensure_vault_directories()
    case_orig_dir = ORIGINALS_DIR / case_id
    case_work_dir = WORKING_DIR / case_id
    case_orig_dir.mkdir(parents=True, exist_ok=True)
    case_work_dir.mkdir(parents=True, exist_ok=True)

    safe_name = f"{evidence_id}_{Path(filename).name}"
    orig_path = case_orig_dir / safe_name
    work_path = case_work_dir / safe_name

    # Compute SHA-256 of raw received bytes
    sha256_hash = calculate_sha256_bytes(content)
    size_bytes = len(content)

    # Write original
    if orig_path.exists():
        # Temporarily make writable if replacing in dev
        os.chmod(orig_path, stat.S_IWRITE | stat.S_IREAD)
    with open(orig_path, "wb") as f:
        f.write(content)
    # Mark original read-only to preserve chain of custody
    try:
        os.chmod(orig_path, stat.S_IREAD)
    except Exception:
        pass

    # Write working copy
    if work_path.exists():
        try:
            os.chmod(work_path, stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass
    with open(work_path, "wb") as f:
        f.write(content)

    return sha256_hash, str(work_path), size_bytes


def verify_evidence_integrity(case_id: str, evidence_id: str, filename: str, expected_hash: str) -> Dict[str, Any]:
    """
    Recomputes SHA-256 of the current working copy and compares against initial expected hash.
    Returns verification status and current hash.
    """
    safe_name = f"{evidence_id}_{Path(filename).name}"
    work_path = WORKING_DIR / case_id / safe_name

    if not work_path.exists():
        return {
            "status": "missing_file",
            "expected_sha256": expected_hash,
            "current_sha256": None,
            "match": False,
            "message": f"Working copy file {safe_name} not found in evidence vault."
        }

    current_hash = calculate_sha256_file(work_path)
    match = (current_hash.lower() == expected_hash.lower())

    return {
        "status": "verified" if match else "mismatch",
        "expected_sha256": expected_hash,
        "current_sha256": current_hash,
        "match": match,
        "message": "SHA-256 cryptographic digest verified successfully." if match else "TAMPER DETECTED: Current file digest differs from initial recorded digest!"
    }


def simulate_tampering_for_demo(case_id: str, evidence_id: str, filename: str) -> Dict[str, Any]:
    """
    Hackathon Demo Tool:
    Flips a single byte in the working copy of an evidence item without touching the preserved original.
    This demonstrates real-time tamper detection to judges!
    """
    safe_name = f"{evidence_id}_{Path(filename).name}"
    work_path = WORKING_DIR / case_id / safe_name

    if not work_path.exists():
        raise FileNotFoundError(f"Working copy {work_path} not found.")

    try:
        os.chmod(work_path, stat.S_IWRITE | stat.S_IREAD)
    except Exception:
        pass

    with open(work_path, "rb") as f:
        data = bytearray(f.read())

    if len(data) > 0:
        # Flip the last byte
        data[-1] = (data[-1] ^ 0xFF)

    with open(work_path, "wb") as f:
        f.write(data)

    new_hash = calculate_sha256_file(work_path)
    return {
        "tampered": True,
        "new_hash": new_hash,
        "message": f"Simulated 1-byte alteration injected into working copy of {filename}. Original remains untouched in immutable vault."
    }


def restore_working_copy_from_original(case_id: str, evidence_id: str, filename: str) -> str:
    """
    Restores the working copy from the untouched read-only original store.
    """
    safe_name = f"{evidence_id}_{Path(filename).name}"
    orig_path = ORIGINALS_DIR / case_id / safe_name
    work_path = WORKING_DIR / case_id / safe_name

    if not orig_path.exists():
        raise FileNotFoundError(f"Original {orig_path} not found.")

    if work_path.exists():
        try:
            os.chmod(work_path, stat.S_IWRITE | stat.S_IREAD)
        except Exception:
            pass

    shutil.copy2(orig_path, work_path)
    try:
        os.chmod(work_path, stat.S_IWRITE | stat.S_IREAD)
    except Exception:
        pass
    return calculate_sha256_file(work_path)
