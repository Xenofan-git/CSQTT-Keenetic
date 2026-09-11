# Build info — CSQTT-Keenetic 0.1.1

Target: Linux ARM64 / Entware `aarch64-k3.10`.

Manager build was verified locally with:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'
```

The MVP intentionally does not change the default route or implement policy routing. The existing Rust CSQTT client remains the transport core.
