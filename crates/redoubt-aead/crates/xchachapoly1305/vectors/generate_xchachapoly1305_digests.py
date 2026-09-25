#!/usr/bin/env python3
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.

"""Writes xchachapoly1305_digests.txt: one digest per message length, from
libsodium.

The answers have to come from libsodium and from nothing else. Regenerating
this file against the implementation it is used to check would freeze whatever
that implementation does today and the test would go on passing for ever
without measuring anything.

Every input is derived rather than written down: a seed is the digest of an
ASCII string, and the key, nonce, associated data and message of a cell come
from that seed with the cell's two lengths in the derivation, so no two cells
share any of them.

The enumeration and the seeds are written into the file's header, and the test
reads them back and holds them to its own: a list changed here and not there is
one failure naming the list, not every row red at once.

Run: python3 vectors/generate_xchachapoly1305_digests.py
"""

import ctypes
import ctypes.util
import sys
from hashlib import sha256
from pathlib import Path

# The enumeration. Both sides walk it in this order: a row per message length,
# inside a row every associated-data length, and inside that every sample.
MSG_LENGTHS = list(range(0, 248)) + [1024, 4095, 4096, 4097, 16384, 65535, 65536, 65537]
AAD_LENGTHS = list(range(0, 56)) + [127, 128, 129, 255, 256, 257, 1024, 4096]
SAMPLES = 2

FIELDS = ("key", "nonce", "aad", "msg")

KEY_SIZE = 32
NONCE_SIZE = 24
TAG_SIZE = 16


def seed(field: str) -> bytes:
    """A field's seed, derived so that there is no hexadecimal to transcribe."""
    return sha256(b"redoubt-xchachapoly1305 corpus " + field.encode()).digest()


def material(field: str, length: int, msg_len: int, aad_len: int, sample: int) -> bytes:
    """The bytes this field takes in this sample of the cell of these two
    lengths."""
    said, counter = b"", 0

    while len(said) < length:
        said += sha256(
            seed(field)
            + length.to_bytes(4, "big")
            + msg_len.to_bytes(4, "big")
            + aad_len.to_bytes(4, "big")
            + sample.to_bytes(4, "big")
            + counter.to_bytes(4, "big")
        ).digest()
        counter += 1

    return said[:length]


def libsodium() -> ctypes.CDLL:
    """libsodium, wherever this machine keeps it.

    PyNaCl ships one inside its own package, which is what makes this work on a
    system that does not expose the library itself.
    """
    candidates = []

    try:
        import nacl._sodium as bundled

        candidates.append(bundled.__file__)
    except ImportError:
        pass

    found = ctypes.util.find_library("sodium")
    if found:
        candidates.append(found)

    for candidate in candidates:
        try:
            loaded = ctypes.CDLL(candidate)
            encrypt = loaded.crypto_aead_xchacha20poly1305_ietf_encrypt_detached
        except (OSError, AttributeError):
            continue

        encrypt.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.c_char_p,
            ctypes.c_ulonglong,
            ctypes.c_char_p,
            ctypes.c_ulonglong,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]

        return loaded

    sys.exit(
        "no libsodium with crypto_aead_xchacha20poly1305_ietf_encrypt_detached "
        "was found. On NixOS, python3Packages.pynacl brings one."
    )


def listed(lengths: list) -> str:
    return ",".join(str(length) for length in lengths)


def main() -> None:
    sodium = libsodium()
    lines = []
    ran = 0

    for msg_len in MSG_LENGTHS:
        row = sha256()

        for aad_len in AAD_LENGTHS:
            for sample in range(SAMPLES):
                key = material("key", KEY_SIZE, msg_len, aad_len, sample)
                nonce = material("nonce", NONCE_SIZE, msg_len, aad_len, sample)
                aad = material("aad", aad_len, msg_len, aad_len, sample)
                msg = material("msg", msg_len, msg_len, aad_len, sample)

                ciphertext = ctypes.create_string_buffer(max(msg_len, 1))
                tag = ctypes.create_string_buffer(TAG_SIZE)
                tag_len = ctypes.c_ulonglong(0)

                if sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
                    ciphertext,
                    tag,
                    ctypes.byref(tag_len),
                    msg,
                    msg_len,
                    aad,
                    aad_len,
                    None,
                    nonce,
                    key,
                ):
                    sys.exit(f"encrypt refused msg {msg_len}, aad {aad_len}")

                if tag_len.value != TAG_SIZE:
                    sys.exit(f"a tag of {tag_len.value} bytes")

                row.update(ciphertext.raw[:msg_len] + tag.raw)
                ran += 1

        lines.append(f"Msg = {msg_len}\nMD = {row.hexdigest()}\n")

    header = (
        "# Auto-generated by generate_xchachapoly1305_digests.py\n"
        "# DO NOT EDIT, and never regenerate against redoubt's own implementation\n"
        "# Source: libsodium crypto_aead_xchacha20poly1305_ietf_encrypt_detached\n"
        "#\n"
        f"# One digest per message length, over {ran} encryptions.\n"
        "# MD is SHA-256 of ciphertext || tag for every aad length and every sample\n"
        "# of that row, concatenated in the order AadLengths lists them and, within\n"
        "# one, sample by sample.\n"
        "\n"
        f"MsgLengths = {listed(MSG_LENGTHS)}\n"
        f"AadLengths = {listed(AAD_LENGTHS)}\n"
        f"Samples = {SAMPLES}\n"
        + "".join(f"Seed {field} = {seed(field).hex()}\n" for field in FIELDS)
        + "\n"
    )

    out = Path(__file__).parent / "xchachapoly1305_digests.txt"
    out.write_text(header + "\n".join(lines))

    print(f"{ran} encryptions, {len(lines)} digests -> {out}")


if __name__ == "__main__":
    main()
