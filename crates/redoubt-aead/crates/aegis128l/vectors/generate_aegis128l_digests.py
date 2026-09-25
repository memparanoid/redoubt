#!/usr/bin/env python3
# Copyright (c) 2025-2026 Federico Hoerth <memparanoid@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# See LICENSE in the repository root for full license text.

"""Writes aegis128l_digests.txt: one digest per message length, from libaegis.

libsodium has AEGIS-128L only with a 256-bit tag, and the tag this crate writes
is the 128-bit one, so the answers come from libaegis, which has both. Before
anything is written, libaegis is held to every encryption the draft publishes:
a library that disagrees with the specification writes no file.

The answers have to come from libaegis and from nothing else. Regenerating
this file against the implementation it is used to check would freeze whatever
that implementation does today and the test would go on passing for ever
without measuring anything.

Every input is derived rather than written down: a seed is the digest of an
ASCII string, and the key, nonce, associated data and message of a cell come
from that seed with the cell's lengths and sample in the derivation. The
enumeration and the seeds are written into the file's header, and the test
reads them back and holds them to its own.

Run inside the image generate_aegis128l_digests.sh builds.
"""

import ctypes
import ctypes.util
import os
import sys
from hashlib import sha256
from pathlib import Path

# The enumeration. Both sides walk it in this order: a row per message length,
# inside a row every associated-data length, and inside that every sample.
MSG_LENGTHS = list(range(0, 248)) + [1024, 4095, 4096, 4097, 16384, 65535, 65536, 65537]
AAD_LENGTHS = list(range(0, 56)) + [127, 128, 129, 255, 256, 257, 1024, 4096]
SAMPLES = 2

FIELDS = ("key", "nonce", "aad", "msg")

KEY_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 16

# draft-irtf-cfrg-aegis-aead-17, appendix A.2: every encryption it publishes,
# as (associated data, message, ciphertext, 128-bit tag), under one key and
# nonce.
DRAFT_KEY = "10010000000000000000000000000000"
DRAFT_NONCE = "10000200000000000000000000000000"
DRAFT = (
    (
        "",
        "00000000000000000000000000000000",
        "c1c0e58bd913006feba00f4b3cc3594e",
        "abe0ece80c24868a226a35d16bdae37a",
    ),
    ("", "", "", "c2b879a67def9d74e6c14f708bbcc9b4"),
    (
        "0001020304050607",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84",
        "cc6f3372f6aa1bb82388d695c3962d9a",
    ),
    (
        "0001020304050607",
        "000102030405060708090a0b0c0d",
        "79d94593d8c2119d7e8fd9b8fc77",
        "5c04b3dba849b2701effbe32c7f0fab7",
    ),
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
        "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10",
        "7542a745733014f9474417b337399507",
    ),
)


def seed(field: str) -> bytes:
    """A field's seed, derived so that there is no hexadecimal to transcribe."""
    return sha256(b"redoubt-aegis128l corpus " + field.encode()).digest()


def material(field: str, length: int, msg_len: int, aad_len: int, sample: int) -> bytes:
    """The bytes this field takes in this sample of the cell of these lengths."""
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


def libaegis() -> ctypes.CDLL:
    """libaegis, as the image installs it, initialised."""
    found = ctypes.util.find_library("aegis") or "/usr/local/lib/libaegis.so"

    try:
        loaded = ctypes.CDLL(found)
    except OSError:
        sys.exit(f"no libaegis at {found}; run this through generate_aegis128l_digests.sh")

    loaded.aegis128l_encrypt_detached.argtypes = [
        ctypes.c_char_p,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_char_p,
    ]

    if loaded.aegis_init():
        sys.exit("aegis_init refused")

    return loaded


def encrypt(aegis: ctypes.CDLL, key: bytes, nonce: bytes, aad: bytes, msg: bytes):
    """Ciphertext and 128-bit tag, or the process ends."""
    ciphertext = ctypes.create_string_buffer(max(len(msg), 1))
    tag = ctypes.create_string_buffer(TAG_SIZE)

    if aegis.aegis128l_encrypt_detached(
        ciphertext, tag, TAG_SIZE, msg, len(msg), aad, len(aad), nonce, key
    ):
        sys.exit(f"encrypt refused msg {len(msg)}, aad {len(aad)}")

    return ciphertext.raw[: len(msg)], tag.raw


def against_the_draft(aegis: ctypes.CDLL) -> None:
    """libaegis agrees with every encryption the draft publishes, or nothing is
    written."""
    key = bytes.fromhex(DRAFT_KEY)
    nonce = bytes.fromhex(DRAFT_NONCE)

    for number, (aad, msg, ct, tag) in enumerate(DRAFT, start=1):
        answer = encrypt(aegis, key, nonce, bytes.fromhex(aad), bytes.fromhex(msg))

        if answer != (bytes.fromhex(ct), bytes.fromhex(tag)):
            sys.exit(f"libaegis disagrees with draft vector {number}")


def listed(lengths: list) -> str:
    return ",".join(str(length) for length in lengths)


def main() -> None:
    aegis = libaegis()
    against_the_draft(aegis)

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

                ciphertext, tag = encrypt(aegis, key, nonce, aad, msg)

                row.update(ciphertext + tag)
                ran += 1

        lines.append(f"Msg = {msg_len}\nMD = {row.hexdigest()}\n")

    version = os.environ.get("LIBAEGIS_VERSION", "unknown")
    header = (
        "# Auto-generated by generate_aegis128l_digests.py\n"
        "# DO NOT EDIT, and never regenerate against redoubt's own implementation\n"
        f"# Source: libaegis {version} aegis128l_encrypt_detached, 128-bit tag,\n"
        "# after agreeing with every encryption of draft-irtf-cfrg-aegis-aead-17 A.2\n"
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

    out = Path(__file__).parent / "aegis128l_digests.txt"
    out.write_text(header + "\n".join(lines))

    print(f"{ran} encryptions, {len(lines)} digests -> {out}")


if __name__ == "__main__":
    main()
