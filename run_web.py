#!/usr/bin/env python3
"""
CLI launcher for api-tool Minimal Testing Web Interface.
Usage:
    python3 run_web.py [--port=8000] [--host=127.0.0.1]
"""

import argparse
import sys
from api_tool.web.server import run_server


def main():
    parser = argparse.ArgumentParser(description="Run api-tool minimal web interface")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
