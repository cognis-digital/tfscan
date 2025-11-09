"""TFSCAN MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from tfscan.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-tfscan[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-tfscan[mcp]'")
        return 1
    app = FastMCP("tfscan")

    @app.tool()
    def tfscan_scan(target: str) -> str:
        """Scan Terraform plans/configs for misconfigurations. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
