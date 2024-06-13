#!/bin/bash

# Check if a command line argument is provided
if [ $# -eq 0 ]
  then
    echo "No arguments supplied. Please provide the major version."
    exit 1
fi

# Get the major version from the command line argument
major_version=$1

# Get the current branch's commit count
commit_count=$(git rev-list --count HEAD)

# Get the current month
current_month=$(date +%m)

# Define the version
version="${major_version}.${current_month}.${commit_count}"

# Create the version.h file
cat << EOF > src/version.h
#ifndef _VERSION_
#define _VERSION_
#define VERSION "${version}"
#endif
EOF
