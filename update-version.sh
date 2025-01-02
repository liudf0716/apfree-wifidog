#!/bin/bash

# Get the current commit count
commit_count=$(git rev-list --count HEAD)

# Define the base version (major.minor)
base_version="8.$(date +%m)"

# Combine base version with commit count
new_version="${base_version}.${commit_count}"

# Update version.h with the new version
sed -i "s/^#define VERSION \".*\"/#define VERSION \"${new_version}\"/" src/version.h

echo "Updated version.h to version ${new_version}"