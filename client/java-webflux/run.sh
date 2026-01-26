#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Check if Maven is available
if command -v mvn &> /dev/null; then
    echo "Using Maven..."
    cd "$SCRIPT_DIR"
    mvn -q compile exec:java -Dexec.args="$*"
elif command -v "/c/ProgramData/chocolatey/lib/maven/apache-maven-3.9.12/bin/mvn" &> /dev/null; then
    echo "Using Maven (Chocolatey)..."
    cd "$SCRIPT_DIR"
    "/c/ProgramData/chocolatey/lib/maven/apache-maven-3.9.12/bin/mvn" -q compile exec:java -Dexec.args="$*"
else
    echo "Error: Maven not found. Please install Maven or use 'mvn compile exec:java' directly."
    echo "Install Maven: choco install maven -y"
    exit 1
fi
