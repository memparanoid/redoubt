#!/usr/bin/env python3
"""
Generates Rust test vectors from Wycheproof JSON.

Usage:
    python3 scripts/generate_wycheproof.py
"""

import json
import os
import urllib.request

# Configuration for multiple test vector sources
TEST_CONFIGS = [
    {
        "name": "XChaCha20-Poly1305",
        "type": "aead",
        "url": "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/xchacha20_poly1305_test.json",
        "output": os.path.join(
            os.path.dirname(__file__),
            "..",
            "crates",
            "memaead",
            "src",
            "xchacha20poly1305",
            "tests",
            "wycheproof_vectors.rs",
        ),
    },
    {
        "name": "AEGIS-128L",
        "type": "aead",
        "url": "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/aegis128L_test.json",
        "output": os.path.join(
            os.path.dirname(__file__),
            "..",
            "crates",
            "memaead",
            "src",
            "aegis",
            "aegis128l",
            "tests",
            "wycheproof_vectors.rs",
        ),
    },
    {
        "name": "HKDF-SHA-512",
        "type": "hkdf",
        "url": "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/hkdf_sha512_test.json",
        "output": os.path.join(
            os.path.dirname(__file__),
            "..",
            "crates",
            "memhkdf",
            "src",
            "tests",
            "wycheproof_vectors.rs",
        ),
    },
]

# AEAD flags
AEAD_FLAG_MAP = {
    # Shared
    "Ktv": "Flag::Ktv",
    "ModifiedTag": "Flag::ModifiedTag",
    "Pseudorandom": "Flag::Pseudorandom",
    # XChaCha20-Poly1305
    "EdgeCaseCiphertext": "Flag::EdgeCaseCiphertext",
    "EdgeCasePoly1305": "Flag::EdgeCasePoly1305",
    "EdgeCasePolyKey": "Flag::EdgeCasePolyKey",
    "EdgeCaseTag": "Flag::EdgeCaseTag",
    "InvalidNonceSize": "Flag::InvalidNonceSize",
    # AEGIS-128L
    "OldVersion": "Flag::OldVersion",
    "TagCollision_1": "Flag::TagCollision1",
    "TagCollision_2": "Flag::TagCollision2",
}

# HKDF flags
HKDF_FLAG_MAP = {
    "Normal": "Flag::Normal",
    "EmptySalt": "Flag::EmptySalt",
    "MaximalOutputSize": "Flag::MaximalOutputSize",
    "SizeTooLarge": "Flag::SizeTooLarge",
    "OutputCollision": "Flag::OutputCollision",
}

RESULT_MAP = {
    "valid": "TestResult::Valid",
    "invalid": "TestResult::Invalid",
    "acceptable": "TestResult::Acceptable",
}


def fetch_json(url):
    """Download Wycheproof test vectors JSON."""
    with urllib.request.urlopen(url) as response:
        return json.loads(response.read().decode("utf-8"))


def map_flags(flags, flag_map):
    """Convert JSON flags array to Rust vec! macro."""
    if not flags:
        return "vec![]"
    rust_flags = [flag_map.get(f, f"/* unknown: {f} */") for f in flags]
    return f"vec![{', '.join(rust_flags)}]"


def map_result(result):
    """Convert JSON result string to Rust enum."""
    return RESULT_MAP.get(result, f"/* unknown: {result} */")


def escape_string(s):
    """Escape a string for Rust."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def generate_aead_rust(data, source_url):
    """Generate Rust source code from Wycheproof AEAD JSON."""
    lines = []

    # Header
    lines.append("// Auto-generated from Wycheproof test vectors")
    lines.append("// DO NOT EDIT - run `python3 scripts/generate_wycheproof.py`")
    lines.append(f"// Source: {source_url}")
    lines.append("//")
    lines.append(f"// Algorithm: {data.get('algorithm', 'unknown')}")
    lines.append(f"// Version: {data.get('generatorVersion', 'unknown')}")
    lines.append(f"// Number of tests: {data.get('numberOfTests', 'unknown')}")
    lines.append("")
    lines.append("use super::wycheproof::{Flag, TestCase, TestResult};")
    lines.append("")
    lines.append("pub(crate) fn test_vectors() -> Vec<TestCase> {")
    lines.append("    vec![")

    # Iterate test groups
    for group in data.get("testGroups", []):
        iv_size = group.get("ivSize", 0)
        key_size = group.get("keySize", 0)
        tag_size = group.get("tagSize", 0)

        lines.append(
            f"        // ivSize: {iv_size}, keySize: {key_size}, tagSize: {tag_size}"
        )

        for test in group.get("tests", []):
            tc_id = test.get("tcId", 0)
            comment = escape_string(test.get("comment", ""))
            flags = map_flags(test.get("flags", []), AEAD_FLAG_MAP)
            key = test.get("key", "")
            iv = test.get("iv", "")
            aad = test.get("aad", "")
            msg = test.get("msg", "")
            ct = test.get("ct", "")
            tag = test.get("tag", "")
            result = map_result(test.get("result", ""))

            lines.append("        TestCase {")
            lines.append(f"            tc_id: {tc_id},")
            lines.append(f'            comment: "{comment}".into(),')
            lines.append(f"            flags: {flags},")
            lines.append(f'            key: "{key}".into(),')
            lines.append(f'            iv: "{iv}".into(),')
            lines.append(f'            aad: "{aad}".into(),')
            lines.append(f'            msg: "{msg}".into(),')
            lines.append(f'            ct: "{ct}".into(),')
            lines.append(f'            tag: "{tag}".into(),')
            lines.append(f"            result: {result},")
            lines.append("        },")

    lines.append("    ]")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def generate_hkdf_rust(data, source_url):
    """Generate Rust source code from Wycheproof HKDF JSON."""
    lines = []

    # Header
    lines.append("// Auto-generated from Wycheproof test vectors")
    lines.append("// DO NOT EDIT - run `python3 scripts/generate_wycheproof.py`")
    lines.append(f"// Source: {source_url}")
    lines.append("//")
    lines.append(f"// Algorithm: {data.get('algorithm', 'unknown')}")
    lines.append(f"// Number of tests: {data.get('numberOfTests', 'unknown')}")
    lines.append("")
    lines.append("extern crate alloc;")
    lines.append("")
    lines.append("use alloc::vec;")
    lines.append("use alloc::vec::Vec;")
    lines.append("")
    lines.append("use super::wycheproof::{Flag, TestCase, TestResult};")
    lines.append("")
    lines.append("pub(crate) fn test_vectors() -> Vec<TestCase> {")
    lines.append("    vec![")

    # Iterate test groups
    for group in data.get("testGroups", []):
        key_size = group.get("keySize", 0)

        lines.append(f"        // keySize: {key_size}")

        for test in group.get("tests", []):
            tc_id = test.get("tcId", 0)
            comment = escape_string(test.get("comment", ""))
            flags = map_flags(test.get("flags", []), HKDF_FLAG_MAP)
            ikm = test.get("ikm", "")
            salt = test.get("salt", "")
            info = test.get("info", "")
            size = test.get("size", 0)
            okm = test.get("okm", "")
            result = map_result(test.get("result", ""))

            lines.append("        TestCase {")
            lines.append(f"            tc_id: {tc_id},")
            lines.append(f'            comment: "{comment}".into(),')
            lines.append(f"            flags: {flags},")
            lines.append(f'            ikm: "{ikm}".into(),')
            lines.append(f'            salt: "{salt}".into(),')
            lines.append(f'            info: "{info}".into(),')
            lines.append(f"            size: {size},")
            lines.append(f'            okm: "{okm}".into(),')
            lines.append(f"            result: {result},")
            lines.append("        },")

    lines.append("    ]")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def main():
    for config in TEST_CONFIGS:
        print(f"\n=== Processing {config['name']} ===")
        print(f"Fetching from {config['url']}...")

        try:
            data = fetch_json(config['url'])
        except Exception as e:
            print(f"ERROR: Failed to fetch {config['name']}: {e}")
            continue

        print(f"Generating Rust code...")

        if config['type'] == 'hkdf':
            rust_code = generate_hkdf_rust(data, config['url'])
        else:
            rust_code = generate_aead_rust(data, config['url'])

        # Ensure output directory exists
        output_path = config['output']
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with open(output_path, "w") as f:
            f.write(rust_code)

        num_tests = data.get("numberOfTests", "?")
        print(f"Written {num_tests} test vectors to {output_path}")

    print("\n✓ All test vectors generated successfully")


if __name__ == "__main__":
    main()
