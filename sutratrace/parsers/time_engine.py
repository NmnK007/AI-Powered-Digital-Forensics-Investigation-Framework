"""
Time Normalization Engine for SutraTrace.
Preserves original timestamp strings, offsets, and records timestamp quality & uncertainty.
"""

from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional
import re
from dateutil import parser as dateutil_parser

# Known timezone mapping offsets in hours
TIMEZONE_OFFSETS = {
    "UTC": 0.0,
    "GMT": 0.0,
    "Z": 0.0,
    "IST": 5.5,
    "ASIA/KOLKATA": 5.5,
    "EST": -5.0,
    "EDT": -4.0,
    "CST": -6.0,
    "CDT": -5.0,
    "PST": -8.0,
    "PDT": -7.0,
}


def normalize_timestamp(
    raw_timestamp_str: str,
    declared_source_tz: Optional[str] = None,
    default_case_tz: str = "UTC"
) -> Tuple[str, str, str, str]:
    """
    Normalizes a timestamp while strictly preserving provenance.
    Returns: (raw_timestamp, timezone_original, timestamp_utc, timestamp_quality)
    """
    raw_str = str(raw_timestamp_str).strip()
    if not raw_str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return raw_str, "None", now, "missing_source_timestamp"

    # Check for Unix epoch (seconds or milliseconds)
    if raw_str.replace('.', '', 1).isdigit():
        val = float(raw_str)
        if val > 1e11:  # milliseconds
            val /= 1000.0
        dt = datetime.fromtimestamp(val, tz=timezone.utc)
        return raw_str, "Unix_Epoch_UTC", dt.strftime("%Y-%m-%dT%H:%M:%SZ"), "verified_utc"

    tz_original = declared_source_tz or ""
    quality = "unverified_local"

    # Detect explicit timezone or offset in the string
    has_explicit_z = raw_str.endswith('Z') or raw_str.endswith('z')
    has_offset = bool(re.search(r'([+-]\d{2}:?\d{2})$', raw_str))

    try:
        dt = dateutil_parser.parse(raw_str)
        if dt.tzinfo is not None:
            # Has timezone info
            dt_utc = dt.astimezone(timezone.utc)
            tz_original = tz_original or str(dt.tzinfo)
            quality = "verified_utc" if has_explicit_z else "source_timezone_declared"
        else:
            # Naive datetime
            effective_tz = (declared_source_tz or default_case_tz or "UTC").upper()
            offset_hours = TIMEZONE_OFFSETS.get(effective_tz, 0.0)
            tz_delta = timedelta(hours=offset_hours)
            dt_utc = dt - tz_delta
            tz_original = declared_source_tz or f"Assumed_{effective_tz}"
            quality = "source_timezone_declared" if declared_source_tz else "unverified_local_assumed"

        utc_iso = dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        return raw_str, tz_original, utc_iso, quality

    except Exception:
        # Fallback if unparseable
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return raw_str, "Unparseable", now, "malformed_timestamp_fallback"
