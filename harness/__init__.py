"""MCP VulnLab harness.

A scanner-agnostic evaluation harness for the MCP VulnLab corpus. Point any MCP
scanner at the corpus, normalize its output, and get a detection-rate scorecard
against labeled ground truth.

Typical use::

    mcp-vulnlab validate
    mcp-vulnlab run --scanner skillspector --out results/skillspector
    mcp-vulnlab report --in results/skillspector
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
