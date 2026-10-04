"""
Headless DOM Execution Engine for api-tool.
Executes client-side JavaScript, intercepts dynamic network calls,
and extracts rendered DOM structures using an isolated happy-dom sidecar.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

RUNNER_SCRIPT = Path(__file__).resolve().parent / "happy_dom_runner.js"


class HappyDOMEngine:
    """Headless DOM execution engine powered by a Node.js happy-dom sidecar process."""

    @classmethod
    def is_available(cls) -> bool:
        """Checks if Node.js runtime and runner script are available."""
        return shutil.which("node") is not None and RUNNER_SCRIPT.is_file()

    @classmethod
    async def evaluate(
        cls,
        url: str,
        html: str,
        scripts: Optional[List[str]] = None,
        timeout: float = 15.0,
    ) -> Dict[str, Any]:
        """Evaluates HTML and optional scripts in a headless DOM environment.

        Args:
            url: The page URL for origin and relative link resolution.
            html: Raw HTML content of the page to evaluate.
            scripts: Optional list of additional JavaScript code strings to evaluate.
            timeout: Subprocess execution timeout in seconds (default 15.0).

        Returns:
            Dictionary containing:
                - 'rendered_html': Fully rendered HTML string.
                - 'dynamic_endpoints': List of intercepted fetch / XHR dynamic calls.
                - 'discovered_links': List of discovered <a href> link URLs.
                - 'forms': List of discovered HTML forms with inputs.
                - 'custom_elements': List of discovered Custom Element tag names.

        Raises:
            RuntimeError: If Node.js is missing or execution returns non-zero.
            TimeoutError: If execution exceeds the specified timeout.
            FileNotFoundError: If the happy_dom_runner.js script is missing.
        """
        node_bin = shutil.which("node")
        if not node_bin:
            raise RuntimeError(
                "Node.js runtime not found in PATH. Install Node.js and happy-dom to use HappyDOMEngine."
            )

        if not RUNNER_SCRIPT.is_file():
            raise FileNotFoundError(f"HappyDOM runner script not found at {RUNNER_SCRIPT}")

        payload = {
            "url": url or "http://localhost",
            "html": html or "",
            "scripts": scripts if scripts is not None else [],
        }

        # Ensure NODE_PATH includes project root node_modules for robust resolution
        env = dict(os.environ)
        repo_root = RUNNER_SCRIPT.parent.parent.parent
        node_modules_path = str(repo_root / "node_modules")
        if os.path.isdir(node_modules_path):
            existing_node_path = env.get("NODE_PATH", "")
            env["NODE_PATH"] = (
                f"{node_modules_path}:{existing_node_path}"
                if existing_node_path
                else node_modules_path
            )

        proc = await asyncio.create_subprocess_exec(
            node_bin,
            str(RUNNER_SCRIPT),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        input_bytes = json.dumps(payload).encode("utf-8")

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(input=input_bytes),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            except Exception as kill_err:
                logger.debug(f"Failed to kill runner process: {kill_err}")
            raise TimeoutError(f"HappyDOM evaluation timed out after {timeout} seconds")

        if proc.returncode != 0:
            error_details = stderr_bytes.decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                f"HappyDOM runner failed with exit code {proc.returncode}: {error_details}"
            )

        raw_output = stdout_bytes.decode("utf-8", errors="replace").strip()
        if not raw_output:
            return {
                "rendered_html": "",
                "dynamic_endpoints": [],
                "discovered_links": [],
                "forms": [],
                "custom_elements": [],
            }

        try:
            parsed = json.loads(raw_output)
            if not isinstance(parsed, dict):
                raise ValueError("Expected dictionary output from runner")
            return parsed
        except json.JSONDecodeError as json_err:
            raise RuntimeError(
                f"Failed to parse HappyDOM runner output as JSON: {json_err}. Raw output: {raw_output[:200]}"
            )
