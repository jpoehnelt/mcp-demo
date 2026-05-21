# MCP Demo

End-to-end demo of the [MCP Authorization profile](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) — OAuth 2.1 with PKCE, Client ID Metadata Documents (CIMD draft-01), and Resource Indicators (RFC 8707).

Three services in one workspace:

| Service             | Role                        |
| ------------------- | --------------------------- |
| `mock-customer-idp` | Authorization Server        |
| `mcp-server`        | Resource Server (MCP tools) |
| `mcp-client`        | Public OAuth client (CLI)   |

The specs in [`specs/`](specs/) are the source of truth — start with [`specs/architecture.md`](specs/architecture.md).
