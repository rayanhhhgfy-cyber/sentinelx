"""Vercel serverless entry point for SentinelX.

Vercel's Python runtime imports this module and serves the ``app`` ASGI
application. All /api/* routes are rewritten here by vercel.json.
"""
import os
import sys

# Make the repo root importable (sentinelx package lives one level up)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinelx.web.server import app  # noqa: E402

# Vercel looks for `app` in api/index.py
__all__ = ["app"]
