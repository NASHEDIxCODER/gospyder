# GoSpyder

GoSpyder is a Go reconnaissance framework for subdomain enumeration, TCP port scanning, directory fuzzing, and WAF detection.

The project is currently organized around a v3 modular architecture: the CLI registers modules through an internal registry, command handlers invoke those modules, and shared services such as configuration, logging, formatting, workspace state, HTTP clients, and error collection live under `internal/`.

> Note: the module framework is in place, but several adapters still contain TODOs for wiring the existing scanner implementations into the new module runtime.

## Features

- Subdomain enumeration module scaffold with active DNS brute-force and passive Certificate Transparency support.
- TCP port scanning implementation with concurrency and retry support.
- Directory/path fuzzing implementation with configurable wordlists.
- WAF detection module scaffold for provider fingerprinting.
- Shared application context and dependency injection through `internal/app`.
- Module registration and execution through `internal/registry`.
- Centralized configuration, logging, output formatting, workspace, and error utilities.
- Built-in wordlists for subdomains and HTTP paths.

## Requirements

- Go `1.25.4` or newer, matching `go.mod`.
- Network access for scan targets and Certificate Transparency sources.

## Installation

Build from source:

```bash
git clone https://github.com/NASHEDIxCODER/gospyder.git
cd gospyder
go build -o gospyder ./cmd/gospyder
```

Or install with Go:

```bash
go install github.com/NASHEDIxCODER/gospyder/cmd/gospyder@latest
```

## Usage

GoSpyder now uses subcommands:

```bash
gospyder [command] [target] [options]
```

Available commands:

| Command | Purpose |
| --- | --- |
| `enum` | Subdomain enumeration |
| `ports` | TCP port scanning |
| `fuzz` | Directory/path fuzzing |
| `waf` | WAF detection |
| `recon` | Run the registered reconnaissance modules in sequence |
| `list` | List registered modules |
| `help [module]` | Show global or module help |

Examples:

```bash
./gospyder help
./gospyder list
./gospyder enum example.com
./gospyder ports example.com
./gospyder fuzz https://example.com
./gospyder waf example.com
./gospyder recon example.com
```

Scan commands save results under `reports/<target>/` by default. Use `--workspace=false` to disable saving for a run.

## Current Defaults

Runtime defaults are defined in `internal/config/config.go`:

| Setting | Default |
| --- | --- |
| Threads | `100` |
| Timeout | `10s` command context timeout |
| Retries | `2` |
| User agent | `GoSpyder/3.0` |
| HTTP timeout | `10s` |
| HTTP redirects | Follow redirects, max `10` |
| Default ports | `22, 80, 443, 8080, 8443, 3000, 5000, 9000` |
| Path wordlist | `wordlists/paths.txt` |
| Output format | `txt` |
| Workspace | Enabled by default, path `./reports` |

Configuration loading currently returns these defaults. YAML loading and CLI flag overrides are planned in code comments but are not implemented yet.

## Project Structure

```text
gospyder/
|-- cmd/
|   `-- gospyder/
|       |-- main.go                 # CLI entry point and module registration
|       `-- handlers/
|           |-- commands.go          # Subcommand handlers
|           `-- handler.go           # Module execution helpers
|-- internal/
|   |-- app/                         # Application context and shared services
|   |-- config/                      # Default runtime configuration
|   |-- crawler/                     # Crawler package placeholder/implementation area
|   |-- errors/                      # Error collection utilities
|   |-- logger/                      # Logger implementation
|   |-- output/                      # Colors and formatting helpers
|   |-- registry/                    # Module interface, options, and registry
|   `-- workspace/                   # Workspace/project state utilities
|-- pkg/
|   |-- enum/                        # Enumeration engine, brute force, recursion, module adapter
|   |-- models/                      # Shared domain models
|   |-- resolver/                    # DNS resolver pool
|   |-- scanner/                     # Port scanner, fuzzer, WAF, scanner module adapters
|   `-- sources/                     # External data sources such as CertStream
|-- tests/
|   |-- fixtures.go                  # Test fixtures
|   |-- mocks/                       # Mock config, errors, logger
|   `-- testdata/                    # Test data directory
|-- wordlists/
|   |-- paths.txt                    # 576 HTTP paths
|   `-- subdomains.txt               # 4,989 subdomain words
|-- ARCHITECTURE_ROADMAP.md
|-- ENHANCEMENTS.md
|-- FEATURES_SUMMARY.txt
|-- IMPROVEMENTS.md
|-- PHASE_0_DETAILED_PLAN.md
|-- TECHNICAL_DEBT.md
|-- TRANSFORMATION_SUMMARY.md
|-- go.mod
|-- go.sum
`-- LICENSE
```

## Architecture

The application starts in `cmd/gospyder/main.go`:

1. Load default configuration from `internal/config`.
2. Initialize shared services with `internal/app`.
3. Register modules in `internal/registry`.
4. Dispatch the selected CLI subcommand through `cmd/gospyder/handlers`.
5. Execute one module or a sequence of modules with shared `registry.Options`.

Registered modules implement:

```go
type Module interface {
    Name() string
    Description() string
    Run(ctx context.Context, opts Options) error
}
```

The current registered modules are:

- `enum` from `pkg/enum`
- `ports` from `pkg/scanner`
- `fuzz` from `pkg/scanner`
- `waf` from `pkg/scanner`

## Development

Run tests:

```bash
go test ./...
```

Build the CLI:

```bash
go build -o gospyder ./cmd/gospyder
```

Add a new module by implementing `internal/registry.Module`, then register it in `registerModules` inside `cmd/gospyder/main.go`.

Minimal module shape:

```go
type ModuleAdapter struct{}

func (m *ModuleAdapter) Name() string {
    return "example"
}

func (m *ModuleAdapter) Description() string {
    return "Example module"
}

func (m *ModuleAdapter) Run(ctx context.Context, opts registry.Options) error {
    target, ok := opts.Flags["target"].(string)
    if !ok {
        return fmt.Errorf("target flag required")
    }

    opts.Logger.Info("Running example module for %s", target)
    return nil
}
```

## Wordlists

Default wordlists live in `wordlists/`:

- `wordlists/subdomains.txt`
- `wordlists/paths.txt`

The command handlers currently pass default wordlist paths into modules. Custom wordlist CLI parsing is not wired into the current subcommand handlers yet.

## Status

This repository is in the middle of a modular architecture transition. The package layout and command registry reflect the new structure, while some scanner adapters still need to call the existing implementations in `pkg/scanner` and `pkg/enum`.

See the roadmap and planning documents for deeper context:

- `ARCHITECTURE_ROADMAP.md`
- `PHASE_0_DETAILED_PLAN.md`
- `TECHNICAL_DEBT.md`
- `TRANSFORMATION_SUMMARY.md`

## License

This project is licensed under the MIT License. See `LICENSE` for details.
