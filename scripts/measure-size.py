"""Compare two executable files and identically compressed, executable-only ZIPs.

Uses only Python's standard library. Does not run or modify either executable.
"""
import argparse
import hashlib
import io
import json
import pathlib
import subprocess
import zipfile


def measure(path):
    path = pathlib.Path(path).resolve(strict=True)
    data = path.read_bytes()
    archive = io.BytesIO()
    # Fixed name, timestamp, permissions and compression for an apples-to-apples comparison.
    entry = zipfile.ZipInfo("ip-scout.exe", date_time=(1980, 1, 1, 0, 0, 0))
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.external_attr = 0o100644 << 16
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        output.writestr(entry, data, compresslevel=9)
    return {
        "path": str(path),
        "exe_bytes": len(data),
        "exe_sha256": hashlib.sha256(data).hexdigest(),
        "exe_only_zip_bytes": len(archive.getvalue()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", required=True)
    parser.add_argument("--after", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    before, after = measure(args.before), measure(args.after)
    report = {
        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
        "build_command": "cargo build --release --locked --target x86_64-pc-windows-msvc",
        "zip_method": "executable only; fixed metadata; Python zipfile DEFLATE level 9",
        "before": before,
        "after": after,
        "saved": {
            key: {
                "bytes": before[key] - after[key],
                "percent": round(100 * (before[key] - after[key]) / before[key], 2),
            }
            for key in ("exe_bytes", "exe_only_zip_bytes")
        },
    }
    path = pathlib.Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
