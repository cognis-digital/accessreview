"""ACCESSREVIEW MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from accessreview.core import build_campaign, load_entitlements

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-accessreview[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-accessreview[mcp]'")
        return 1
    app = FastMCP("accessreview")

    @app.tool()
    def accessreview_scan(entitlements_json: str) -> str:
        """Run a UAR campaign from an entitlements JSON string. Returns JSON findings."""
        import json as _json
        ents = load_entitlements(entitlements_json)
        campaign = build_campaign(ents)
        return _json.dumps(campaign.to_dict(), indent=2)

    app.run()
    return 0
