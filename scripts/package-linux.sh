#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$project_root"
target="x86_64-unknown-linux-gnu"
cargo build --release --locked --target "$target"
# cargo pkgid and metadata are machine interfaces; avoid inferring the version from a filename.
package_id="$(cargo pkgid --locked)"
version="${package_id##*@}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || { echo "Cannot determine IP Scout version: $package_id" >&2; exit 1; }
target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then target_dir="$project_root/$target_dir"; fi
name="IP-Scout-$version-Linux-x64"
mkdir -p -- "$project_root/dist"
# A fresh staging directory prevents unrelated or stale files entering a new archive.
stage="$(mktemp -d "$project_root/dist/.linux-package.XXXXXXXX")"
trap 'rm -rf -- "$stage"' EXIT
mkdir -p -- "$stage/$name"
install -m755 -- "$target_dir/$target/release/ip-scout" "$stage/$name/ip-scout"
install -m644 -- README.md LICENSE THIRD_PARTY_NOTICES.md "$stage/$name/"
archive="$project_root/dist/$name.tar.gz"
tar -C "$stage" -czf "$archive" "$name"
(cd -- "$project_root/dist" && sha256sum "$name.tar.gz" > "IP-Scout-$version-Linux-x64-SHA256SUMS.txt")
printf 'Created %s\n' "$archive"
