"""
DexRipper - ctypes binding for libdexcore

Loads the pre-compiled core library and maps C API to Python.
Falls back to pure-Python implementations if the native library is unavailable.
"""

import ctypes
import ctypes.util
import os
import platform
import struct
import hashlib
import glob
from pathlib import Path
from typing import Optional

# ========================================================================
# Library Loading
# ========================================================================

_lib = None
_lib_loaded = False


def _find_lib() -> Optional[str]:
    """Locate libdexcore.so in the lib/ directory or system paths."""
    # Check relative to this file
    pkg_dir = Path(__file__).parent.parent
    arch_map = {
        ("Linux", "aarch64"): "arm64",
        ("Linux", "armv7l"): "armv7",
        ("Linux", "x86_64"): "x86_64",
        ("Linux", "AMD64"): "x86_64",
    }
    system = platform.system()
    machine = platform.machine()
    arch = arch_map.get((system, machine), machine)

    # Try lib/<arch>/libdexcore.so
    candidate = pkg_dir / "lib" / arch / "libdexcore.so"
    if candidate.exists():
        return str(candidate)

    # Try lib/libdexcore.so (host build)
    candidate = pkg_dir / "lib" / "libdexcore.so"
    if candidate.exists():
        return str(candidate)

    # Try system paths
    path = ctypes.util.find_library("dexcore")
    if path:
        return path

    return None


def load_lib() -> bool:
    """Load the native library. Returns True if successful."""
    global _lib, _lib_loaded
    if _lib_loaded:
        return True

    path = _find_lib()
    if not path:
        return False

    try:
        _lib = ctypes.CDLL(path)
        _setup_functions()
        _lib_loaded = True
        return True
    except OSError:
        return False


def _setup_functions():
    """Configure ctypes function signatures."""
    if not _lib:
        return

    # dexcore_version
    _lib.dexcore_version.restype = ctypes.c_char_p
    _lib.dexcore_version.argtypes = []

    # dexcore_config_init
    _lib.dexcore_config_init.restype = None
    _lib.dexcore_config_init.argtypes = [ctypes.POINTER(ScanConfig)]

    # dexcore_scan
    _lib.dexcore_scan.restype = ctypes.c_int
    _lib.dexcore_scan.argtypes = [
        ctypes.POINTER(ScanConfig),
        ctypes.POINTER(ctypes.POINTER(DexResult)),
        ctypes.POINTER(ctypes.c_int),
    ]

    # dexcore_validate
    _lib.dexcore_validate.restype = ctypes.c_int
    _lib.dexcore_validate.argtypes = [ctypes.c_char_p]

    # dexcore_dedup
    _lib.dexcore_dedup.restype = ctypes.c_int
    _lib.dexcore_dedup.argtypes = [ctypes.c_char_p, ctypes.c_char_p]

    # dexcore_repair
    _lib.dexcore_repair.restype = ctypes.c_int
    _lib.dexcore_repair.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]

    # dexcore_free_results
    _lib.dexcore_free_results.restype = None
    _lib.dexcore_free_results.argtypes = [ctypes.POINTER(DexResult), ctypes.c_int]

    # dexcore_ebpf_available
    _lib.dexcore_ebpf_available.restype = ctypes.c_int
    _lib.dexcore_ebpf_available.argtypes = []

    # dexcore_resolve_pid
    _lib.dexcore_resolve_pid.restype = ctypes.c_int
    _lib.dexcore_resolve_pid.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]

    # dexcore_status_str
    _lib.dexcore_status_str.restype = ctypes.c_char_p
    _lib.dexcore_status_str.argtypes = [ctypes.c_int]

    # dexcore_source_str
    _lib.dexcore_source_str.restype = ctypes.c_char_p
    _lib.dexcore_source_str.argtypes = [ctypes.c_int]


# ========================================================================
# C Structure Mirrors
# ========================================================================

class ScanConfig(ctypes.Structure):
    _fields_ = [
        ("mode", ctypes.c_int),
        ("package", ctypes.c_char_p),
        ("output_dir", ctypes.c_char_p),
        ("min_dex_size", ctypes.c_uint32),
        ("enable_repair", ctypes.c_int),
        ("enable_dedup", ctypes.c_int),
        ("num_threads", ctypes.c_int),
        ("verbose", ctypes.c_int),
        ("libart_path", ctypes.c_char_p),
        ("clean_oat", ctypes.c_int),
    ]


class DexResult(ctypes.Structure):
    _fields_ = [
        ("path", ctypes.c_char * 512),
        ("address", ctypes.c_uint64),
        ("size", ctypes.c_uint32),
        ("class_count", ctypes.c_uint32),
        ("method_count", ctypes.c_uint32),
        ("string_count", ctypes.c_uint32),
        ("type_count", ctypes.c_uint32),
        ("version", ctypes.c_char * 4),
        ("adler_ok", ctypes.c_int),
        ("is_duplicate", ctypes.c_int),
        ("status", ctypes.c_int),
        ("source_type", ctypes.c_int),
        ("sha256_short", ctypes.c_char * 17),
        ("sha256", ctypes.c_char * 65),
        ("source", ctypes.c_char * 256),
        ("repair_level", ctypes.c_int),
    ]


# ========================================================================
# Enums
# ========================================================================

MODE_SCAN = 0
MODE_EBPF = 1
MODE_AUTO = 2

DEX_VALID = 0
DEX_ADLER_MISMATCH = 1
DEX_HEADER_BAD = 2
DEX_SIZE_MISMATCH = 3
DEX_NO_CLASSES = 4
DEX_TOO_SMALL = 5
DEX_DUPLICATE = 6
DEX_FILTERED = 7

STATUS_NAMES = {
    DEX_VALID: "VALID",
    DEX_ADLER_MISMATCH: "ADLER_MISMATCH",
    DEX_HEADER_BAD: "HEADER_BAD",
    DEX_SIZE_MISMATCH: "SIZE_MISMATCH",
    DEX_NO_CLASSES: "NO_CLASSES",
    DEX_TOO_SMALL: "TOO_SMALL",
    DEX_DUPLICATE: "DUPLICATE",
    DEX_FILTERED: "FILTERED",
}


# ========================================================================
# Python Fallback Implementations (when native lib unavailable)
# ========================================================================

def py_adler32(data: bytes) -> int:
    """Compute Adler-32 checksum."""
    a, b = 1, 0
    for byte in data:
        a = (a + byte) % 65521
        b = (b + a) % 65521
    return (b << 16) | a


def py_validate_dex(path: str) -> dict:
    """Pure-Python DEX validation (fallback when native lib unavailable)."""
    result = {
        "path": path,
        "valid": False,
        "status": DEX_TOO_SMALL,
        "size": 0,
        "version": "",
        "class_count": 0,
        "method_count": 0,
        "string_count": 0,
        "type_count": 0,
        "adler_ok": False,
        "sha256": "",
    }

    try:
        with open(path, "rb") as f:
            data = f.read()
    except (OSError, IOError):
        return result

    size = len(data)
    result["size"] = size

    if size < 0x70:
        return result

    # Magic
    if data[:4] != b"dex\n":
        result["status"] = DEX_HEADER_BAD
        return result

    result["version"] = data[4:7].decode("ascii", errors="replace")

    # Header size
    header_size = struct.unpack_from("<I", data, 0x24)[0]
    if header_size != 0x70:
        result["status"] = DEX_HEADER_BAD
        return result

    # Endian tag
    endian = struct.unpack_from("<I", data, 0x28)[0]
    if endian != 0x12345678:
        result["status"] = DEX_HEADER_BAD
        return result

    # File size
    declared_size = struct.unpack_from("<I", data, 0x20)[0]
    if declared_size != size:
        result["status"] = DEX_SIZE_MISMATCH
        return result

    # class_defs
    class_defs = struct.unpack_from("<I", data, 0x60)[0]
    result["class_count"] = class_defs
    if class_defs == 0:
        result["status"] = DEX_NO_CLASSES
        return result

    # Other counts
    result["string_count"] = struct.unpack_from("<I", data, 0x38)[0]
    result["type_count"] = struct.unpack_from("<I", data, 0x40)[0]
    result["method_count"] = struct.unpack_from("<I", data, 0x58)[0]

    # Adler-32
    stored_adler = struct.unpack_from("<I", data, 0x08)[0]
    calc_adler = py_adler32(data[0x0C:size])
    result["adler_ok"] = calc_adler == stored_adler

    # SHA-256
    result["sha256"] = hashlib.sha256(data).hexdigest()

    result["valid"] = result["adler_ok"]
    result["status"] = DEX_VALID if result["adler_ok"] else DEX_ADLER_MISMATCH
    return result


def py_dedup_dir(input_dir: str, output_dir: Optional[str] = None) -> int:
    """Pure-Python deduplication."""
    dex_files = sorted(glob.glob(os.path.join(input_dir, "*.dex")))
    seen = {}
    removed = 0
    out = output_dir or input_dir
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    for path in dex_files:
        with open(path, "rb") as f:
            sha = hashlib.sha256(f.read()).hexdigest()

        if sha in seen:
            removed += 1
            if not output_dir:
                os.unlink(path)
        else:
            seen[sha] = path
            if output_dir and output_dir != input_dir:
                import shutil
                shutil.copy2(path, os.path.join(output_dir, os.path.basename(path)))

    return removed


def py_repair_dex(path: str, level: int = 0) -> bool:
    """Pure-Python DEX repair (level 0: Adler-32 only)."""
    try:
        with open(path, "rb") as f:
            data = bytearray(f.read())
    except (OSError, IOError):
        return False

    if len(data) < 0x70:
        return False

    if level >= 0:
        # Fix Adler-32
        adler = py_adler32(bytes(data[0x0C:]))
        struct.pack_into("<I", data, 0x08, adler)

    if level >= 1:
        # Fix file_size
        struct.pack_into("<I", data, 0x20, len(data))
        # Fix header_size
        struct.pack_into("<I", data, 0x24, 0x70)
        # Fix endian
        struct.pack_into("<I", data, 0x28, 0x12345678)
        # Re-fix Adler-32
        adler = py_adler32(bytes(data[0x0C:]))
        struct.pack_into("<I", data, 0x08, adler)

    try:
        with open(path, "wb") as f:
            f.write(data)
        return True
    except (OSError, IOError):
        return False


# ========================================================================
# Unified API (native with Python fallback)
# ========================================================================

def get_version() -> str:
    """Get core library version."""
    if load_lib():
        return _lib.dexcore_version().decode("utf-8")
    return "1.0.0-py"


def validate(path: str) -> dict:
    """Validate a DEX file."""
    if load_lib():
        result = DexResult()
        ret = _lib.dexcore_validate_ex(path.encode(), ctypes.byref(result))
        if ret == 0:
            return _dex_result_to_dict(result)
    return py_validate_dex(path)


def dedup(input_dir: str, output_dir: Optional[str] = None) -> int:
    """Deduplicate DEX files."""
    if load_lib():
        out = output_dir.encode() if output_dir else None
        return _lib.dexcore_dedup(input_dir.encode(), out)
    return py_dedup_dir(input_dir, output_dir)


def repair(input_dir: str, output_dir: Optional[str] = None, level: int = 0) -> int:
    """Repair DEX files."""
    if load_lib():
        out = output_dir.encode() if output_dir else None
        return _lib.dexcore_repair(input_dir.encode(), out, level)
    # Python fallback: repair each file
    count = 0
    for path in glob.glob(os.path.join(input_dir, "*.dex")):
        if py_repair_dex(path, level):
            count += 1
    return count


def _dex_result_to_dict(r: DexResult) -> dict:
    """Convert DexResult ctypes struct to Python dict."""
    return {
        "path": r.path.decode("utf-8", errors="replace"),
        "address": r.address,
        "size": r.size,
        "class_count": r.class_count,
        "method_count": r.method_count,
        "string_count": r.string_count,
        "type_count": r.type_count,
        "version": r.version.decode("utf-8", errors="replace"),
        "adler_ok": bool(r.adler_ok),
        "is_duplicate": bool(r.is_duplicate),
        "status": r.status,
        "status_str": STATUS_NAMES.get(r.status, "UNKNOWN"),
        "source_type": r.source_type,
        "sha256_short": r.sha256_short.decode("utf-8", errors="replace"),
        "sha256": r.sha256.decode("utf-8", errors="replace"),
        "source": r.source.decode("utf-8", errors="replace"),
        "repair_level": r.repair_level,
    }
