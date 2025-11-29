#!/usr/bin/env python3
"""
Generates Rust test vectors from Wycheproof XChaCha20-Poly1305 JSON.

Usage:
    python3 crates/memaead/scripts/generate_wycheproof.py
"""

import json
import os
import urllib.request

WYCHEPROOF_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/xchacha20_poly1305_test.json"
OUTPUT_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "crates",
    "memaead",
    "src",
    "xchacha20poly1305",
    "tests",
    "wycheproof_vectors.rs",
)

FLAG_MAP = {
    "EdgeCaseCiphertext": "Flag::EdgeCaseCiphertext",
    "EdgeCasePoly1305": "Flag::EdgeCasePoly1305",
    "EdgeCasePolyKey": "Flag::EdgeCasePolyKey",
    "EdgeCasePolyKey": "Flag::EdgeCasePolyKey",
    "EdgeCaseTag": "Flag::EdgeCaseTag",
    "InvalidNonceSize": "Flag::InvalidNonceSize",
    "Ktv": "Flag::Ktv",
    "ModifiedTag": "Flag::ModifiedTag",
    "Pseudorandom": "Flag::Pseudorandom",
}

RESULT_MAP = {
    "valid": "TestResult::Valid",
    "invalid": "TestResult::Invalid",
    "acceptable": "TestResult::Acceptable",
}


def fetch_json():
    """Download Wycheproof test vectors JSON."""
    with urllib.request.urlopen(WYCHEPROOF_URL) as response:
        return json.loads(response.read().decode("utf-8"))


def map_flags(flags):
    """Convert JSON flags array to Rust vec! macro."""
    if not flags:
        return "vec![]"
    rust_flags = [FLAG_MAP.get(f, f"/* unknown: {f} */") for f in flags]
    return f"vec![{', '.join(rust_flags)}]"


def map_result(result):
    """Convert JSON result string to Rust enum."""
    return RESULT_MAP.get(result, f"/* unknown: {result} */")


def escape_string(s):
    """Escape a string for Rust."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def generate_rust(data):
    """Generate Rust source code from Wycheproof JSON."""
    lines = []

    # Header
    lines.append("// Auto-generated from Wycheproof test vectors")
    lines.append("// DO NOT EDIT - run `python3 scripts/generate_wycheproof.py`")
    lines.append(f"// Source: {WYCHEPROOF_URL}")
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
            flags = map_flags(test.get("flags", []))
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


def main():
    print(f"Fetching Wycheproof test vectors...")
    data = fetch_json()

    print(f"Generating Rust code...")
    rust_code = generate_rust(data)

    # Ensure output directory exists
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    with open(OUTPUT_PATH, "w") as f:
        f.write(rust_code)

    num_tests = data.get("numberOfTests", "?")
    print(f"Written {num_tests} test vectors to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
