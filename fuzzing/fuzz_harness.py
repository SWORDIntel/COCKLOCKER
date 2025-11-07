#!/usr/bin/env python3
"""
CockLocker Fuzzing Harness
Test Cockpit endpoints for vulnerabilities
"""

import sys
import json
import socket
import urllib.parse
from typing import Optional


class CockpitFuzzer:
    """Fuzzing harness for Cockpit endpoints"""

    def __init__(self, host: str = "127.0.0.1", port: int = 9090):
        self.host = host
        self.port = port

    def send_http_request(self, method: str, path: str, body: Optional[str] = None, headers: Optional[dict] = None) -> tuple:
        """Send raw HTTP request to Cockpit"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.host, self.port))

            # Build HTTP request
            request = f"{method} {path} HTTP/1.1\r\n"
            request += f"Host: {self.host}:{self.port}\r\n"

            if headers:
                for key, value in headers.items():
                    request += f"{key}: {value}\r\n"

            if body:
                request += f"Content-Length: {len(body)}\r\n"
                request += "Content-Type: application/json\r\n"

            request += "Connection: close\r\n"
            request += "\r\n"

            if body:
                request += body

            sock.sendall(request.encode())

            # Receive response
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk

            sock.close()

            return response.decode('utf-8', errors='ignore'), None

        except Exception as e:
            return None, str(e)

    def fuzz_auth(self, payload: dict):
        """Fuzz authentication endpoint"""
        try:
            response, error = self.send_http_request(
                "POST",
                "/cockpit/login",
                json.dumps(payload)
            )

            if error:
                print(f"[!] Error: {error}", file=sys.stderr)
                return

            # Check for crashes or unexpected responses
            if response:
                if "500 Internal Server Error" in response:
                    print(f"[!] CRASH DETECTED with payload: {payload}", file=sys.stderr)
                    with open("crashes/auth_crash.txt", "a") as f:
                        f.write(f"{json.dumps(payload)}\n{response}\n\n")

                # Check for injection success indicators
                if "root:" in response or "/etc/passwd" in response:
                    print(f"[!] INJECTION DETECTED: {payload}", file=sys.stderr)

        except Exception as e:
            print(f"[!] Exception during fuzzing: {e}", file=sys.stderr)

    def fuzz_command(self, payload: dict):
        """Fuzz command execution endpoint"""
        try:
            response, error = self.send_http_request(
                "POST",
                "/cockpit/system/terminal",
                json.dumps(payload)
            )

            if error:
                print(f"[!] Error: {error}", file=sys.stderr)
                return

            if response:
                # Check for command injection
                if any(keyword in response for keyword in ["root:", "uid=0", "Permission denied"]):
                    print(f"[!] POTENTIAL COMMAND INJECTION: {payload}", file=sys.stderr)

                if "500" in response or "segmentation fault" in response.lower():
                    print(f"[!] CRASH DETECTED: {payload}", file=sys.stderr)
                    with open("crashes/command_crash.txt", "a") as f:
                        f.write(f"{json.dumps(payload)}\n{response}\n\n")

        except Exception as e:
            print(f"[!] Exception during fuzzing: {e}", file=sys.stderr)


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <auth|command> <input_file>")
        sys.exit(1)

    fuzz_type = sys.argv[1]
    input_file = sys.argv[2]

    # Read fuzzing input
    try:
        with open(input_file, 'rb') as f:
            data = f.read()

        # Try to parse as JSON
        try:
            payload = json.loads(data)
        except json.JSONDecodeError:
            # Use raw data as string payload
            payload = {"data": data.decode('utf-8', errors='ignore')}

        fuzzer = CockpitFuzzer()

        if fuzz_type == "auth":
            fuzzer.fuzz_auth(payload)
        elif fuzz_type == "command":
            fuzzer.fuzz_command(payload)
        else:
            print(f"Unknown fuzz type: {fuzz_type}")
            sys.exit(1)

    except Exception as e:
        print(f"[!] Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
