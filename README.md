# mcp-gate

Two commands, no dependencies, for a local npm MCP server:

- **pack** writes `server.json` (schema `2025-12-11`, npm + stdio) and `mcp-checksums.json`. It inserts `mcpName` when the GitHub owner can be read from `repository`. It does not publish.
- **verify** starts the package bin over stdio, sends `initialize` and `tools/list`, and scores the static checks below. It does not call any tool.

A finding fails the run. A warning does not.

## Checks

OWASP MCP Top 10 (2025, still in beta). The rules are pattern and shape checks.

| Id | What is checked |
|---|---|
| MCP01 | Secret-shaped strings in the shipped files, the description, or a tool schema |
| MCP03 | Hidden-instruction phrases; `readOnlyHint` / `destructiveHint` disagreeing with the description; a tool missing its name, description, or schema |
| MCP04 | `mcpName` matches `server.json`, pinned version, npm registry URL, lockfile when dependencies exist, checksums |
| MCP05 | A free-form `command` / `shell` / `script` parameter. Missing `additionalProperties: false` is a warning |
| MCP07 | The bin exists and speaks stdio. A remote, or a non-stdio transport, fails. `runtimeHint: npx` is a warning |
| MCP09 | The file being verified is the bin the package installs. A process that announces a different name is a warning |

Out of scope, because each one needs a tool call and a judgment of the transcript: **MCP02, MCP06, MCP08, MCP10**.

## Use

```powershell
npx -y @dalainarwhal/mcp-gate pack C:\path\to\server
npx -y @dalainarwhal/mcp-gate verify C:\path\to\server
node server.mjs --selftest
```

On Windows, launch it with `cmd /c npx`, not `npx` alone. This packager does not write `runtimeHint: npx`.

MCP server, for an agent:

```json
{
  "mcpServers": {
    "mcp-gate": {
      "command": "node",
      "args": ["C:/Users/dalai/Documents/projects/mcp-gate/server.mjs"]
    }
  }
}
```

Tools: `pack_server`, `verify_server`. Both take `directory`. `verify_server` takes an optional `entry`, and refuses it when it is not the package bin.
