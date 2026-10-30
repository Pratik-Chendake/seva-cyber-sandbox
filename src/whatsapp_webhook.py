"""
Standalone Lightweight HTTP Webhook Server for WhatsApp Cloud API Integration.
Part of Seva Cyber Sandbox.

Built using Python's standard library http.server (zero third-party web framework dependencies).
Can be run locally or behind reverse proxies (ngrok, Cloudflare Tunnel, AWS ALB, Nginx).

CLI Execution:
    python src/whatsapp_webhook.py --port 8000
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
import urllib.parse

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.whatsapp_handler import (
    load_whatsapp_config,
    process_incoming_webhook_event,
)


class WhatsAppWebhookRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for WhatsApp Cloud API webhooks."""

    server_version = "SevaSandboxWebhook/1.0"

    def _send_json_response(self, status_code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text_response(self, status_code: int, text: str):
        body = text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """
        Handles:
        1. /health: Webhook service health check.
        2. /webhook: Meta Cloud API Webhook Verification Challenge.
        """
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        # Health endpoint
        if path in ("/health", "/"):
            cfg = load_whatsapp_config()
            self._send_json_response(
                200,
                {
                    "service": "Seva Cyber Sandbox — WhatsApp Cloud API Webhook",
                    "status": "healthy",
                    "mode": cfg["mode"],
                    "has_live_credentials": cfg["has_live_credentials"],
                    "timestamp": cfg.get("api_version"),
                },
            )
            return

        # Meta Webhook verification handshake
        if path == "/webhook":
            cfg = load_whatsapp_config()
            mode = query_params.get("hub.mode", [""])[0]
            token = query_params.get("hub.verify_token", [""])[0]
            challenge = query_params.get("hub.challenge", [""])[0]

            expected_token = cfg["verify_token"]

            if mode == "subscribe" and token == expected_token:
                # Handshake success: echo back the challenge
                self._send_text_response(200, challenge)
            else:
                self._send_json_response(
                    403,
                    {
                        "error": "Forbidden: Verification token mismatch.",
                        "mode": mode,
                        "hint": "Check WHATSAPP_VERIFY_TOKEN in environment variables.",
                    },
                )
            return

        self._send_json_response(404, {"error": "Not Found"})

    def do_POST(self):
        """
        Handles incoming WhatsApp message events sent to /webhook.
        """
        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path != "/webhook":
            self._send_json_response(404, {"error": "Not Found"})
            return

        # Read content-length
        content_length_header = self.headers.get("Content-Length")
        if not content_length_header or not content_length_header.isdigit():
            self._send_json_response(411, {"error": "Length Required"})
            return

        content_length = int(content_length_header)
        if content_length > 16 * 1024 * 1024:  # 16 MB max
            self._send_json_response(413, {"error": "Payload Too Large (Max 16 MB)"})
            return

        raw_body = self.rfile.read(content_length)
        signature = self.headers.get("X-Hub-Signature-256")

        result = process_incoming_webhook_event(
            raw_payload_bytes=raw_body,
            signature_header=signature,
        )

        status_code = result.get("status_code", 200)
        self._send_json_response(status_code, result)


def run_webhook_server(host: str = "0.0.0.0", port: int = 8000) -> ThreadingHTTPServer:
    """Starts the threaded webhook HTTP server."""
    server = ThreadingHTTPServer((host, port), WhatsAppWebhookRequestHandler)
    print(f"[*] Seva Cyber Sandbox WhatsApp Webhook Server listening on http://{host}:{port}/webhook")
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seva Cyber Sandbox WhatsApp Webhook Service")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    args = parser.parse_args()

    cfg = load_whatsapp_config()
    print("=" * 70)
    print("Seva Cyber Sandbox — WhatsApp Cloud API Webhook Listener")
    print(f"Mode: {'LIVE' if cfg['mode'] == 'live' else 'SIMULATION / STANDBY'}")
    print(f"Verify Token Configured: {bool(cfg['verify_token'])}")
    print(f"App Secret Configured:   {bool(cfg['app_secret'])}")
    print(f"Phone Number ID:         {cfg['phone_number_id'] or 'Not Set (Simulation Only)'}")
    print("=" * 70)

    srv = run_webhook_server(host=args.host, port=args.port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping WhatsApp Webhook Server...")
        srv.server_close()
