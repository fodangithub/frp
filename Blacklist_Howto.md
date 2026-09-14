# frps IP Blacklist — Setup & Maintenance Howto

This fork of frp supports server-side IP blacklisting: connections from
blacklisted IPs are rejected immediately at the TCP level, both for frpc
control connections (`server/service.go`) and for user connections to
proxies (`server/proxy/proxy.go`). The logic lives in `pkg/blacklist`.

The blacklist has **two independent parts** that are checked together:

| Part | Source | Lifetime | frps.ini key(s) |
|------|--------|----------|-----------------|
| **Static** | local file(s) you maintain | loaded once at startup, never replaced or overwritten | `blacklist_additional_files` |
| **Dynamic** | remote URLs (e.g. Spamhaus DROP) | re-fetched every `blacklist_refresh_interval` seconds | `blacklist_urls`, `blacklist_file_path` (cache) |

## 1. The static list (your own entries)

Create a file with your entries, e.g. `blacklist_additional.json`:

```json
[
  {"cidr": "185.247.137.0/24"},
  {"cidr": "85.217.149.0/24"},
  {"cidr": "203.0.113.7"},
  {"cidr": "2001:db8:abcd::/48"}
]
```

Rules:
- Individual IPs and CIDR ranges are supported, IPv4 and IPv6.
- Both `"cidr"` and `"network"` field names are accepted; NDJSON (one JSON
  object per line, e.g. the Spamhaus DROP format) is accepted too, and
  `"type": "metadata"` lines are ignored.
- Reference it in `frps.ini` (comma-separate multiple files):

```ini
blacklist_additional_files = ./blacklist_additional.json
```

- These files are **read-only for frps**: they are loaded once when frps
  starts and are never modified afterwards.
- **Static entries are only re-read on restart.** After editing, restart
  frps (see §4).
- A missing or malformed additional file is skipped with a warning in the
  log — it will not prevent frps from starting, but check the log after
  restart to make sure your entries loaded.

## 2. The dynamic list (auto-updated URL feeds)

```ini
blacklist_urls = https://www.spamhaus.org/drop/drop_v4.json,https://www.spamhaus.org/drop/drop_v6.json
blacklist_refresh_interval = 3600
```

- All URL responses are merged and atomically replace the dynamic set every
  `blacklist_refresh_interval` seconds (0 disables auto-refresh; one fetch
  still happens at startup). No restart needed for updates.
- `blacklist_file_path` (e.g. `./blacklist.json`) seeds the dynamic set at
  startup and is **overwritten with the fetched content on every successful
  fetch** — it is a cache, not a place for your own entries. If all URL
  fetches fail, the last cached content keeps being enforced.

## 3. Full example

```ini
[common]
bind_port = 7000

# dynamic: Spamhaus DROP feeds, refreshed hourly, cached in blacklist.json
blacklist_file_path = ./blacklist.json
blacklist_urls = https://www.spamhaus.org/drop/drop_v4.json,https://www.spamhaus.org/drop/drop_v6.json
blacklist_refresh_interval = 3600

# static: your own entries, never overwritten (changes need a restart)
blacklist_additional_files = ./blacklist_additional.json
```

A sample static file is at `conf/blacklist_sample.json` in this repo.

## 4. Deployed server layout (47.100.213.9)

Everything lives in `/home/fodan/frps/` and runs as user `fodan`:

```
/home/fodan/frps/
├── frps_linux                  # server binary (this fork)
├── frps.ini                    # config (blacklist keys above are active)
├── blacklist.json              # dynamic cache, auto-overwritten by URL fetches — do not hand-edit
├── blacklist_additional.json   # static entries — edit this one, then restart
├── start_frps.sh               # start script (nohup, --tls_only)
├── certs/ new-certs/           # TLS material (mTLS, tls_only)
└── frps.log                    # log (log_max_days = 3)
```

The process is started manually (the files in `systemd/` are templates for
`/etc/frp`, not the active unit):

```sh
# find and stop the running instance
pkill -f 'frps_linux -c'
# start it again
sh /home/fodan/frps/start_frps.sh
```

Restarting drops current client connections; frpc reconnects automatically
within ~10 seconds.

## 5. Verifying

After a restart, the log shows what was loaded:

```sh
grep blacklist /home/fodan/frps/frps.log
# expect lines like:
#   blacklist: loaded N IPs and M CIDR ranges from additional file ./blacklist_additional.json
#   blacklist: refreshed N IPs and M CIDR ranges from 2 URLs
```

A rejected connection produces:

```
blacklist: rejected connection from <ip>:<port>          (control connections)
blacklist: rejected user connection from <ip>:<port>     (proxy/user connections)
```

Quick functional check from any machine (replace the port with the actual
`bind_port`): a blacklisted source IP gets its TCP connection closed
immediately after connect, before any frp handshake.

## 6. Common pitfalls

- Put your own entries in `blacklist_additional.json`, **not** in
  `blacklist.json` (the latter is overwritten on every URL refresh).
- Static file changes require a restart; URL changes do not.
- If a file referenced by `blacklist_additional_files` does not exist or
  fails to parse, frps starts anyway but skips it — check the log.
- The blacklist matches the remote TCP peer address only; it does not do
  DNS/hostname matching.
