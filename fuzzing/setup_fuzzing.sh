#!/bin/bash
# CockLocker Fuzzing Infrastructure Setup
# Continuous security testing inspired by ImageHarden

set -euo pipefail

echo "[*] Setting up CockLocker fuzzing infrastructure..."

# Check for AFL++ or libFuzzer
if ! command -v afl-fuzz &> /dev/null; then
    echo "[*] Installing AFL++ for fuzzing..."
    apt-get update
    apt-get install -y afl++ clang llvm
fi

# Create fuzzing directories
mkdir -p fuzzing/{inputs,outputs,crashes,corpus}

echo "[*] Creating fuzzing corpus for Cockpit..."

# Create sample inputs for various Cockpit interfaces
cat > fuzzing/inputs/valid_login.json << 'EOF'
{
    "user": "admin",
    "password": "test123",
    "path": "/cockpit/login"
}
EOF

cat > fuzzing/inputs/valid_command.json << 'EOF'
{
    "command": "systemctl status",
    "path": "/cockpit/system"
}
EOF

cat > fuzzing/inputs/malicious_injection.json << 'EOF'
{
    "user": "admin'; DROP TABLE users; --",
    "password": "' OR '1'='1",
    "path": "../../../../../etc/passwd"
}
EOF

cat > fuzzing/inputs/xss_payload.json << 'EOF'
{
    "input": "<script>alert('XSS')</script>",
    "path": "<img src=x onerror=alert(1)>"
}
EOF

echo "[+] Fuzzing corpus created"

# Create fuzzing wrapper for Cockpit
cat > fuzzing/fuzz_cockpit.sh << 'EOFUZZ'
#!/bin/bash
# Fuzzing wrapper for Cockpit HTTP endpoints

set -euo pipefail

COCKPIT_PORT=9090
CORPUS_DIR="./inputs"
CRASHES_DIR="./crashes"
OUTPUTS_DIR="./outputs"

mkdir -p "$CRASHES_DIR" "$OUTPUTS_DIR"

echo "[*] Starting Cockpit fuzzing campaign..."
echo "[*] Target: localhost:$COCKPIT_PORT"

# Fuzz authentication endpoint
echo "[*] Fuzzing authentication endpoint..."
afl-fuzz -i "$CORPUS_DIR" -o "$OUTPUTS_DIR/auth" -m none -- \
    python3 ../monitoring/fuzz_harness.py auth @@

# Fuzz command execution
echo "[*] Fuzzing command execution..."
afl-fuzz -i "$CORPUS_DIR" -o "$OUTPUTS_DIR/command" -m none -- \
    python3 ../monitoring/fuzz_harness.py command @@

echo "[+] Fuzzing campaign complete. Check $OUTPUTS_DIR for results."
EOFUZZ

chmod +x fuzzing/fuzz_cockpit.sh

echo "[+] Fuzzing infrastructure setup complete!"
echo ""
echo "To start fuzzing:"
echo "  cd fuzzing"
echo "  ./fuzz_cockpit.sh"
