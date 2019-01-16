# Standalone ANDDOS

An attempt to rewrite, extend and distribute ANDDOS as a standalone service. It should rely on ReverseProxy from golang net/httputil package.

Under development.

## Usage

Command line

```
$ anddos_go --help
Usage of ./anddos_go:
  -listenPort string
        Port where ANDDOS should listen (default ":8080")
  -upstreamURL string
        URL to protected server (default "http://localhost:80")
$ anddos_go
```

### Statically linked (mostly) build

```
CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' .
```

### Docker Image

TODO