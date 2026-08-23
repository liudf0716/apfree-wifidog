#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_REPO="${SOURCE_REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"

# Default paths for chawrt OpenWrt tree
DEFAULT_MAKEFILE="/media/windows/github/chawrt/chawrt/feeds/packages/net/apfree-wifidog/Makefile"
if [[ ! -f "$DEFAULT_MAKEFILE" && -f "$HOME/Windows/github/chawrt/chawrt/feeds/packages/net/apfree-wifidog/Makefile" ]]; then
  DEFAULT_MAKEFILE="$HOME/Windows/github/chawrt/chawrt/feeds/packages/net/apfree-wifidog/Makefile"
fi

DEFAULT_DL="/media/windows/github/chawrt/chawrt/dl"
if [[ ! -d "$DEFAULT_DL" && -d "$HOME/Windows/github/chawrt/chawrt/dl" ]]; then
  DEFAULT_DL="$HOME/Windows/github/chawrt/chawrt/dl"
fi

PACKAGE_MAKEFILE="${PACKAGE_MAKEFILE:-$DEFAULT_MAKEFILE}"
DL_DIR="${DL_DIR:-$DEFAULT_DL}"

if [[ ! -f "$PACKAGE_MAKEFILE" ]]; then
  echo "Makefile not found: $PACKAGE_MAKEFILE" >&2
  exit 1
fi

if [[ ! -d "$SOURCE_REPO/.git" ]]; then
  echo "Git repository not found: $SOURCE_REPO" >&2
  exit 1
fi

# Sync PKG_VERSION from src/version.h if available
if [[ -f "$SOURCE_REPO/src/version.h" ]]; then
  header_version="$(sed -n 's/.*VERSION *"\(.*\)".*/\1/p' "$SOURCE_REPO/src/version.h" | head -n1)"
  if [[ -n "$header_version" ]]; then
    sed -i "s/^PKG_VERSION:=.*/PKG_VERSION:=${header_version}/" "$PACKAGE_MAKEFILE"
  fi
fi

pkg_name="$(sed -n 's/^PKG_NAME:=//p' "$PACKAGE_MAKEFILE" | head -n1)"
pkg_version="$(sed -n 's/^PKG_VERSION:=//p' "$PACKAGE_MAKEFILE" | head -n1)"

if [[ -z "$pkg_name" || -z "$pkg_version" ]]; then
  echo "Failed to parse PKG_NAME or PKG_VERSION from $PACKAGE_MAKEFILE" >&2
  exit 1
fi

archive_name="${pkg_name}-${pkg_version}.tar.gz"
prefix_dir="${pkg_name}-${pkg_version}"
tmp_archive="$(mktemp "/tmp/${pkg_name}-${pkg_version}.XXXXXX.tar.gz")"

mkdir -p "$DL_DIR"
trap 'rm -f "$tmp_archive"' EXIT

git -C "$SOURCE_REPO" archive \
  --format=tar.gz \
  --prefix="${prefix_dir}/" \
  -o "$tmp_archive" \
  HEAD

mv -f "$tmp_archive" "$DL_DIR/$archive_name"
chmod 0644 "$DL_DIR/$archive_name"
trap - EXIT

new_hash="$(sha256sum "$DL_DIR/$archive_name" | awk '{print $1}')"
if [[ ! "$new_hash" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Failed to compute SHA256 for $DL_DIR/$archive_name" >&2
  exit 1
fi

old_hash="$(sed -n 's/^PKG_HASH:=//p' "$PACKAGE_MAKEFILE" | head -n1)"
if ! grep -q '^PKG_HASH:=' "$PACKAGE_MAKEFILE"; then
  echo "PKG_HASH not found in $PACKAGE_MAKEFILE" >&2
  exit 1
fi

sed -i "s/^PKG_HASH:=.*/PKG_HASH:=${new_hash}/" "$PACKAGE_MAKEFILE"

echo "Created: $DL_DIR/$archive_name"
echo "Updated $PACKAGE_MAKEFILE:"
echo "  PKG_VERSION: ${pkg_version}"
echo "  PKG_HASH:"
echo "    old: ${old_hash:-<empty>}"
echo "    new: ${new_hash}"
