# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

frp is a fast reverse proxy that exposes local servers behind NAT/firewalls to the Internet. It consists of two binaries: **frps** (server, runs on a public-IP host) and **frpc** (client, runs in the LAN). Proxy types: `tcp`, `udp`, `http`, `https`, `tcpmux` (HTTP CONNECT), `stcp` (secret TCP), `sudp`, `xtcp` (P2P NAT traversal).

**This is a fork** (`fodangithub/frp`, branch `custom-v0.38.0-server-patches`) based on upstream frp v0.38.0 (`pkg/util/version/version.go` pins `0.38.0`). It backports server-side security/leak fixes from later releases **without changing the `pkg/msg` wire protocol**, so stock v0.38.0 frpc binaries remain compatible. Preserve this invariant: do not alter message types/fields in `pkg/msg` or the token-auth crypto on the control connection.

Fork-specific features (not in upstream):
- **Server-side IP blacklist** — `pkg/blacklist.Manager` rejects blacklisted IPs/CIDRs. Configured via frps.ini keys `blacklist_file_path` (dynamic cache file, overwritten on every successful URL fetch), `blacklist_urls` (comma-separated), `blacklist_refresh_interval` (seconds), and `blacklist_additional_files` (comma-separated local files loaded once at startup into a static set, never replaced or overwritten by URL refreshes). Accepts a JSON array of `{"network": "..."}` objects or NDJSON (Spamhaus-style, `"cidr"` field). The Manager keeps separate static/dynamic sets; `IsBlacklisted` checks both. Enforced in two places: `server/service.go` (frpc control/work connections) and `server/proxy/proxy.go` `startListenHandler` (user connections to proxies). Sample data: `conf/blacklist_sample.json`.
- **Dashboard "Clients" view** — `/api/clients` endpoint (`APIClients` in `server/dashboard_api.go`, backed by `ControlManager.List()` and `Control.GetLoginMsg/GetRemoteAddr/GetProxies`) plus `web/frps/src/components/Clients.vue`. Dashboard default bind was changed to `127.0.0.1:7500`.

## Build Commands

```bash
make            # go fmt + build both binaries into ./bin/
make frps       # build only frps
make frpc       # build only frpc
make -f Makefile.cross-compiles   # release builds for all OS/arch into ./release/
```

Builds use `CGO_ENABLED=0` with `-trimpath -ldflags "-s -w"`. The Makefiles use Unix shell syntax (`env VAR=...`, `rm`, `cp`); run them under bash (Git Bash on Windows) or invoke `go build ./cmd/frps` directly.

### Web UI (dashboard / admin UI)

The Vue frontends live in `web/frps/` and `web/frpc/` (yarn/npm, `make` in each dir runs `npm run build`). Built output is copied into `assets/frps/static/` and `assets/frpc/static/` via `make file` at repo root, then compiled into the binaries with `go:embed` (`assets/frps/embed.go`, registered into `assets/assets.go`). If you change anything under `web/`, you must rebuild the frontend, run `make file`, and commit the regenerated `assets/*/static` files — the Go binary serves only the embedded copy.

## Testing

```bash
make gotest     # unit tests for assets/, cmd/, client/, server/, pkg/ (go test -v --cover)
make e2e        # full e2e suite (hack/run-e2e.sh); requires ./bin/frpc and ./bin/frps built first
make alltest    # gotest + e2e (what CI runs)
```

Run a single unit test:

```bash
go test ./pkg/blacklist/ -run TestIsBlacklisted_JSONArray -v
```

E2E uses **Ginkgo v1** (`hack/run-e2e.sh` installs `ginkgo@latest` if missing, runs `-nodes=8`). To run a subset, invoke ginkgo directly with `-focus`:

```bash
ginkgo -focus="TCP" ./test/e2e -- -frpc-path=./bin/frpc -frps-path=./bin/frps -log-level=debug
DEBUG=true LOG_LEVEL=trace ./hack/run-e2e.sh   # verbose e2e
```

E2E tests spawn real frps/frpc processes (`test/e2e/framework`): `framework.NewDefaultFramework()` gives port allocation (range 20000–50000, partitioned per parallel node), temp config files rendered from Go templates (`{{ .PortName }}` placeholders resolved by `RenderTemplates`), mock TCP/UDP/HTTP echo servers (`test/e2e/mock`), and process lifecycle management. Tests start from `consts.DefaultServerConfig` / `consts.DefaultClientConfig` (`test/e2e/framework/consts`). Suites are organized as `test/e2e/basic/` (core behaviors), `test/e2e/features/`, `test/e2e/plugin/`.

## Architecture

### Runtime hierarchy

Both sides follow **Service → Control → Proxy**:

- **frps** (`server/`): `Service` (`server/service.go`) owns all listeners and the `ResourceController` (`server/controller/resource.go`, field `rc`) which aggregates shared managers: port managers (`server/ports`), visitor manager (`server/visitor`), HTTP vhost router (`pkg/util/vhost`), HTTPS/tcpmux muxers, group controllers (`server/group`), and the blacklist manager. Each connected frpc gets a `Control` (`server/control.go`, managed by `ControlManager`). Each registered proxy becomes a `server/proxy.Proxy` implementation (one file per type; `BaseProxy.startListenHandler` is the common listener-accept loop).
- **frpc** (`client/`): `Service` (`client/service.go`) handles login/reconnect (`login_fail_exit` controls retry-vs-exit), then one `Control` (`client/control.go`) manages the control connection: reader/writer/msgHandler/worker goroutines, heartbeat, proxy registration, and work-connection handling. `client/proxy/proxy_manager.go` + `proxy_wrapper.go` run each proxy; `client/proxy/proxy.go` has per-type `InWorkConn` handlers. Visitors (`stcp`/`sudp`/`xtcp` with `role = visitor`) are handled by `client/visitor.go` / `visitor_manager.go`.

### Connection lifecycle (data path)

1. frpc logs in over the control connection (`msg.Login`, authenticated by token or OIDC — `pkg/auth`). With `tcp_mux` (default on), all logical connections multiplex over one TCP conn via yamux.
2. frpc sends `msg.NewProxy` per proxy; frps allocates the listener/port via `rc` and replies `NewProxyResp`.
3. A user connection arriving at frps makes the proxy request a **work connection** from frpc (`ReqWorkConn`/`NewWorkConn`/`StartWorkConn`), which frpc bridges to the local service (`InWorkConn`). Pre-established pools (`pool_count` / `max_pool_count`) avoid per-request dial latency.
4. UDP is tunneled by packing datagrams into `msg.UDPPacket` over the control channel (`pkg/proto/udp`); xtcp does NAT hole punching via frps's UDP port (`pkg/nathole`, `server/service.go` nathole controller).

### Wire protocol (`pkg/msg`)

Each message is a single-byte type tag + JSON payload (`msgTypeMap` in `msg.go`). Types: Login/LoginResp, NewProxy/NewProxyResp, CloseProxy, NewWorkConn/ReqWorkConn/StartWorkConn, NewVisitorConn(+Resp), Ping/Pong, UDPPacket, NatHole*. **Fork constraint: keep this wire-compatible with v0.38.0.**

### Port sharing on `bind_port`

`server/service.go` uses `golib/net/mux` to sniff the first bytes of incoming connections on `bind_port` and dispatch to: frp control channel (default), frp-TLS (first byte `0x17`, or `0x16` when not sharing with https vhost), websocket (`GET /~!frp`), or HTTP/HTTPS vhost when `vhost_http_port`/`vhost_https_port` equals `bind_port`. KCP listens on its own UDP port (`kcp_bind_port`).

### Configuration (`pkg/config`)

INI files parsed with `gopkg.in/ini.v1` in two steps (see `pkg/config/README.md`): basic field matching via struct tags, then custom parsing for maps/arrays (e.g. `http_plugins.*`, `metas`, header_ prefixes). Config files are Go templates rendered with environment variables before parsing (`GetRenderedConfFromFile` in `value.go`; syntax `{{ .Envs.FRP_SERVER_ADDR }}`). Key types: `ClientCommonConf`/`ServerCommonConf`, and the `ProxyConf`/`VisitorConf` interface hierarchies in `proxy.go`/`visitor.go` (one `*ProxyConf` struct per proxy type, all embedding `BaseProxyConf`). Full option reference: `conf/frps_full.ini` and `conf/frpc_full.ini`.

### Plugins

- **Client plugins** (`pkg/plugin/client`): registered by name via `Register(name, CreatorFn)`; config params use the `plugin_` prefix and arrive as a `map[string]string`. Built-ins: `unix_domain_socket`, `http_proxy`, `socks5`, `static_file`, `http2https`, `https2http`, `https2https`. A plugin handles connections instead of forwarding to `local_ip:local_port`.
- **Server plugins** (`pkg/plugin/server`): HTTP webhook hooks on lifecycle events (Login, NewProxy, CloseProxy, Ping, NewWorkConn, NewUserConn), configured via `http_plugin_*` keys; see `doc/server_plugin.md` and `tracer.go`.

### Metrics & logging

`pkg/metrics` (aggregate/mem/prometheus) — Prometheus exposition requires dashboard enabled plus `enable_prometheus = true`. Logging goes through `pkg/util/log` (global) and `pkg/util/xlog` (per-request context loggers carried in `context.Context`).
