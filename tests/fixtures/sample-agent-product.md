# Pocket Glossary

Translate a short technical phrase into a plain-language explanation. This
file is a local test fixture for the hackathon product, not a live service.

## Requirements

Python 3.10 or newer. No package installation is required.

## CLI

From the `product` folder:

```sh
python3 tests/fixtures/pocket_glossary.py --json '{"term":"MCP"}'
```

The command emits one JSON object to stdout. Example output:

```json
{"term":"MCP","definition":"A protocol for connecting an AI client to tools and context."}
```

Exit code is zero on success. If `term` is missing, the program emits a JSON
error to stderr and returns exit code 2. This is a read-only command.

## MCP

Stdio server config: `command: python3`, `args: ["-m", "agent_service.mcp"]`,
working directory: `product`. This fixture's actual script only implements
the CLI example; MCP here documents the outer product's transport scaffold.
