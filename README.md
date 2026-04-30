# template-repository

Go template repository with two runnable examples:
- `template-repository`: the original hello-world CLI binary
- `web`: a Go web server that embeds a React frontend into a single binary

[![Go Report Card](https://goreportcard.com/badge/github.com/jimyag/template-repository)](https://goreportcard.com/report/github.com/jimyag/template-repository)
[![codecov](https://codecov.io/gh/jimyag/template-repository/branch/main/graph/badge.svg)](https://codecov.io/gh/jimyag/template-repository)
[![License](https://img.shields.io/github/license/jimyag/template-repository)](LICENSE)
[![Release](https://img.shields.io/github/v/release/jimyag/template-repository)](https://github.com/jimyag/template-repository/releases)

## Installation

### From release

Download the latest binaries from [Releases](https://github.com/jimyag/template-repository/releases).

### From source

```bash
go install github.com/jimyag/template-repository/cmd/template-repository@latest
go install github.com/jimyag/template-repository/cmd/web@latest
```

### Docker

```bash
docker pull ghcr.io/jimyag/template-repository:latest
```

## Usage

### CLI example

```bash
template-repository
```

### Web example

Run the Go web server:

```bash
go run ./cmd/web
```

The server listens on `:8080` by default. Override it with:

```bash
WEB_LISTEN_ADDR=:3000 go run ./cmd/web
```

The embedded frontend includes these example routes:

- `/`: home page
- `/dynamic`: list/detail/nested route example
- `/state`: Zustand shared state example
- `/api-demo`: axios request/loading/error/cancel example
- `/form`: controlled form and validation example

API endpoints exposed by the Go server:

- `GET /api/items`
- `GET /api/items/:id`

## Development

### Requirements

- Go `1.26+`
- [bun](https://bun.sh/) `1.2.21+`
- `task` for the convenience commands below

### Frontend development

Start the Go API server:

```bash
go run ./cmd/web
```

In another terminal, start the Vite dev server:

```bash
cd web-vite
bun install
bun run dev
```

Vite proxies `/api` to `http://localhost:8080`.

### Build

```bash
# Install tools
task deps

# Install frontend dependencies
cd web-vite && bun install

# Run linters
task lint

# Run tests
task test

# Build frontend and both Go binaries
task build
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache 2.0](LICENSE)
