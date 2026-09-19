#!/usr/bin/env python3
"""Recover the cipher keys statically from your own ``bitwig.jar``.

All three keys are ordinary ``byte[]`` literals in the jar. They are built by
bytecode (``newarray byte`` followed by one ``bastore`` per element), so the
bytes are interleaved with opcodes and never appear as a contiguous run. A
``grep`` over the jar finds nothing in any encoding. Reading the arrays out of
the bytecode finds all three.

    python examples/extract_keys_from_jar.py
    python examples/extract_keys_from_jar.py --jar /path/to/bitwig.jar --write

Every candidate is verified against your own installed archives before it is
reported: a wrong key yields high-entropy garbage, a right one yields content
with the structure its container promises. Nothing here prints key material
unless you ask for ``--hex``.

This reads YOUR own licensed install and writes to YOUR own disk. It ships no
keys and no Bitwig content.
"""
from __future__ import annotations

import argparse
import hashlib
import struct
import sys
import zipfile
from pathlib import Path

from bitwig_nitro import write_keys_file
from bitwig_nitro.dag_cipher import dag_decrypt

# Where a stock install keeps the jar and the two archives, per platform.
MAC_APP = Path("/Applications/Bitwig Studio.app")
JAR_RELATIVE = ("Contents/Java/bitwig.jar", "bin/bitwig.jar", "lib/bitwig/bitwig.jar")

# The factory key is at least 48 bytes: the cipher factory rejects anything
# shorter with "Key too short".
MIN_KEY = 48

# ``newarray`` with the operand for ``byte``. Every array literal starts here.
NEWARRAY_BYTE = b"\xbc\x08"


# ---------------------------------------------------------------------------
# reading byte[] literals out of bytecode
# ---------------------------------------------------------------------------


def _push(code: bytes, i: int) -> tuple[int | None, int]:
    """Decode one integer-push instruction. Returns (value, next offset)."""
    op = code[i]
    if 0x02 <= op <= 0x08:  # iconst_m1 .. iconst_5
        return op - 0x03, i + 1
    if op == 0x10:  # bipush
        return struct.unpack(">b", code[i + 1 : i + 2])[0], i + 2
    if op == 0x11:  # sipush
        return struct.unpack(">h", code[i + 1 : i + 3])[0], i + 3
    return None, i


def byte_array_literals(class_bytes: bytes, minimum: int = MIN_KEY) -> list[bytes]:
    """Every ``byte[]`` built by a run of ``bastore``, in class-file order.

    Scans the whole class rather than parsing the code attributes: the pattern
    ``newarray byte`` then repeated ``dup / <index> / <value> / bastore`` is
    unambiguous enough that a false positive would have to be a run of valid
    pushes ending in 0x54, which does not occur in practice.
    """
    out: list[bytes] = []
    i = 0
    while i < len(class_bytes) - 2:
        if class_bytes[i] == 0xBC and class_bytes[i + 1] == 0x08:  # newarray byte
            j = i + 2
            values: dict[int, int] = {}
            while j < len(class_bytes) - 1 and class_bytes[j] == 0x59:  # dup
                index, j2 = _push(class_bytes, j + 1)
                if index is None:
                    break
                value, j3 = _push(class_bytes, j2)
                if value is None or j3 >= len(class_bytes) or class_bytes[j3] != 0x54:
                    break
                values[index] = value & 0xFF
                j = j3 + 1
            if len(values) >= minimum and set(values) == set(range(len(values))):
                out.append(bytes(values[k] for k in range(len(values))))
            i = j
        else:
            i += 1
    return out


def candidates(jar_path: Path) -> dict[bytes, list[str]]:
    """Every distinct long ``byte[]`` literal in the jar, and where it is.

    Every class is looked at. The keys sit in three different packages, so
    narrowing to the packages they occupy today would stop finding them the
    release one moves. What is skipped is the walk: a class with no
    ``newarray byte`` in it cannot hold an array literal, and that check is a
    substring search rather than a Python loop over every byte. On a 6.1 jar
    that is 281 classes walked instead of 31,476. No candidate is missed by it,
    since the pattern being looked for starts with those two bytes.
    """
    found: dict[bytes, list[str]] = {}
    with zipfile.ZipFile(jar_path) as jar:
        for entry in jar.namelist():
            if not entry.endswith(".class"):
                continue
            class_bytes = jar.read(entry)
            if NEWARRAY_BYTE not in class_bytes:
                continue
            for array in byte_array_literals(class_bytes):
                found.setdefault(array, []).append(entry)
    return found


# ---------------------------------------------------------------------------
# verifying a candidate against your own install
# ---------------------------------------------------------------------------


def verify_nitro_image(key: bytes, image: Path) -> bool:
    """Decrypt one member and look for its own name in the plaintext.

    Checked this way rather than by decompiling, so the test does not also
    assert the nitrobin format version: a 5.1.9 image decrypts correctly under
    this key but does not parse with a decompiler written for 6.x. The member
    name is stored near the start of every entry, and a wrong key would have to
    produce it by chance out of high-entropy noise.
    """
    with zipfile.ZipFile(image) as archive:
        name = archive.namelist()[0]
        raw = archive.read(name)
    stem = Path(name).stem.encode("utf-8")
    return stem in _strip(raw, key)[:256]


def verify_nitro_std(key: bytes, std: Path) -> bool:
    """Decrypt one member and check it is Nitro source rather than noise."""
    with zipfile.ZipFile(std) as archive:
        raw = archive.read(archive.namelist()[0])
    try:
        text = _strip(raw, key).decode("utf-8")
    except UnicodeDecodeError:
        return False
    return any(word in text for word in ("template ", "import ", "struct ", "static const"))


def verify_dag(key: bytes, document: Path) -> bool:
    """Decrypt a ``0004`` document's metadata section and look for its fields.

    The header is 42 ASCII bytes; the metadata section follows, prefixed by a
    version byte and a 16-byte IV.
    """
    raw = document.read_bytes()
    if not raw.startswith(b"BtWg"):
        return False
    body = raw[42:]
    plain = dag_decrypt(body[17:], key, body[1:17])
    return b"device_uuid" in plain or b"meta" in plain


def _strip(raw: bytes, key: bytes) -> bytes:
    """Split a stored member into IV and ciphertext, then decrypt.

    Both archives store ``[version][iv][ciphertext]``, and the IV is twice the
    key length, which is what the chain's ``iv_size`` field reports: 198 for the
    99-byte nitro-image key, 192 for the 96-byte nitro-std key.
    """
    iv_size = len(key) * 2
    return dag_decrypt(raw[1 + iv_size :], key, raw[1 : 1 + iv_size])


# ---------------------------------------------------------------------------
# locating the install
# ---------------------------------------------------------------------------


def find_jar(install: Path) -> Path:
    for relative in JAR_RELATIVE:
        candidate = install / relative
        if candidate.is_file():
            return candidate
    raise SystemExit(f"no bitwig.jar under {install}")


def find_library(install: Path) -> Path:
    for relative in ("Contents/Resources/Library", "Library", "lib/bitwig/Library"):
        candidate = install / relative
        if candidate.is_dir():
            return candidate
    raise SystemExit(f"no Library directory under {install}")


def a_factory_document(library: Path) -> Path | None:
    for path in sorted((library / "devices").glob("*.bwdevice")):
        return path
    return None


# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--install", type=Path, default=MAC_APP, help="Bitwig install root")
    parser.add_argument("--jar", type=Path, help="bitwig.jar (default: inside --install)")
    parser.add_argument("--hex", action="store_true", help="print the key material")
    parser.add_argument("--write", action="store_true", help="write keys.json")
    args = parser.parse_args()

    jar = args.jar or find_jar(args.install)
    library = find_library(args.install)
    image, std = library / "nitro-image", library / "nitro-std"
    document = a_factory_document(library)

    print(f"scanning {jar}")
    found = candidates(jar)
    print(f"{len(found)} byte[] literal(s) of {MIN_KEY}+ bytes\n")

    keys: dict[str, bytes] = {}
    for array, where in sorted(found.items(), key=lambda kv: len(kv[0])):
        role = "unidentified"
        if image.is_file() and verify_nitro_image(array, image):
            role, keys["nitro_image"] = "nitro-image key", array
        elif std.is_file() and verify_nitro_std(array, std):
            role, keys["nitro_std"] = "nitro-std key", array
        elif document is not None and verify_dag(array, document):
            role, keys["dag"] = "Dag key (0004 documents)", array
        digest = hashlib.sha256(array).hexdigest()[:12]
        print(f"  {len(array):>4} bytes  sha256:{digest}  {role}")
        print(f"        in {where[0]}")
        if args.hex and role != "unidentified":
            print(f"        {array.hex()}")

    if not keys:
        print("\nnothing verified. Check that --install points at a real Bitwig.")
        return 1

    print(f"\nverified {len(keys)} key(s): {', '.join(sorted(keys))}")
    if args.write:
        path = write_keys_file(
            dag_key_hex=keys["dag"].hex() if "dag" in keys else None,
            image_key_hex=keys["nitro_image"].hex() if "nitro_image" in keys else None,
        )
        print(f"wrote {path}")
    else:
        print("re-run with --write to store them in keys.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
