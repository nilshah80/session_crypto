#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
SRC_DIR="$SCRIPT_DIR/src/main/java"
OUT_DIR="$SCRIPT_DIR/out"

# Create directories
mkdir -p "$LIB_DIR" "$OUT_DIR"

# Download Jackson if not present
if [ ! -f "$LIB_DIR/jackson-databind-2.18.3.jar" ]; then
    echo "Downloading dependencies..."
    curl -sL -o "$LIB_DIR/jackson-databind-2.18.3.jar" "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.18.3/jackson-databind-2.18.3.jar"
    curl -sL -o "$LIB_DIR/jackson-core-2.18.3.jar" "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/2.18.3/jackson-core-2.18.3.jar"
    curl -sL -o "$LIB_DIR/jackson-annotations-2.18.3.jar" "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-annotations/2.18.3/jackson-annotations-2.18.3.jar"
fi

# Compile
echo "Compiling..."
javac --enable-preview --source 25 -cp "$LIB_DIR/*" -d "$OUT_DIR" "$SRC_DIR/com/example/SessionCryptoClient.java"

# Run
echo "Running..."
java --enable-preview -cp "$OUT_DIR:$LIB_DIR/*" com.example.SessionCryptoClient "$@"
