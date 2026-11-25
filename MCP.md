# MCP: Connecting AI assistants to tools

Least privilege; read-only by default; confirm before destructive actions. **Verify package names and options in each server's official README.** Antigravity config path (verify for your version): `$HOME/.gemini/config/mcp_config.json`.

## Useful servers
| Server | Why | Access |
|---|---|---|
| Filesystem | Edit docs, Ryu app, configs | Project folder only |
| GitHub | Issues/PRs | Read-only token first |
| Docs/fetch | Look up Ryu, OVS, Suricata, AWS docs (the PDF cites official docs for every clarification) | Read-only |

**Not recommended:** an MCP server with shell access to the lab host or AWS admin rights. A mistaken command could change flow rules or cloud retention (hard to reverse).

## Config snippets (placeholders only)
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/ABSOLUTE/PATH/sdn-threat-isolation"]
    },
    "github": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "<SET_IN_YOUR_ENVIRONMENT>" }
    }
  }
}
```
For a docs/fetch server, follow its own README and keep it read-only.

## Allowed vs blocked
- **Allowed:** read files, search docs, read issues, propose edits.
- **Ask first:** writing outside `docs/`, `controller/`, `risk/`, `audit/`; PRs; pushes.
- **Blocked:** executing OpenFlow commands against a live switch, running attack traffic, AWS write/delete (especially S3 Object Lock or retention changes), reading `.env` or key material, deleting files/branches.

## Safety rules
1. Read-only by default. 2. Confirm before destructive actions, naming what will change. 3. Scoped tokens, no admin. 4. No keys in prompts or committed files. 5. Assistant never touches production or non-lab networks.

## Testing connections
Filesystem: list `docs/`. GitHub: list issues. Docs: fetch one official page and cite it.

## Troubleshooting
| Symptom | Fix |
|---|---|
| Server not listed | Restart IDE; validate JSON |
| `npx`/`docker` not found | Install; fix PATH |
| 401 GitHub | New token with minimal scopes |
| No tools appear | Check server logs; Docker running |
| Assistant invents OpenFlow/Suricata options | Require a citation to official docs |
