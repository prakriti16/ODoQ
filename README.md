# ODoQ testbed (stage 1)

Controlled, single-host testbed for Oblivious DNS-over-QUIC (ODoQ) and DNS-over-QUIC (DoQ).
Every protocol runs on the same emulated topology, the same QUIC stack, the same resolver
and the same caching policy, and every query is logged with nanosecond timestamps from one
shared clock.

Stage 2 will add DoH2, DoH3, ODoH over HTTP/2 and HTTP/3, an HPKE variant of ODoQ, and plotting.

## What changed from the original code

| Original code | This testbed |
|---|---|
| Proxy opened a new QUIC connection to the resolver per query and relayed the answer only after the connection's closing period (3 x PTO) | `persistent` mode keeps one upstream connection; the old behaviour is kept as `legacy` mode so its cost can be measured |
| Resolver forwarded to 8.8.8.8 over plaintext UDP with a blocking call | Local Unbound recursing to a local NSD; asynchronous backend client with TCP fallback |
| Only the first stream chunk was read | Every stream is buffered until FIN |
| `--insecure` everywhere | Private CA; every certificate is verified |
| TLS private key reused as the RSA-OAEP key | Dedicated target key (`certs/target_key.pem`) |
| Nonce = millisecond timestamp | 16 random bytes; AES-GCM associated data separates queries from responses |
| AES-256 query key, AES-128 response key | AES-128 for both |
| No RFC 9250 length prefix | 2-byte length prefix on every stream |
| Domain-mismatch check silently ignored | Response id, qname and qtype checked; mismatches logged as failures |
| Keys and payloads printed to stdout | No secrets in logs; TLS keys go to NSS key-log files for Wireshark |
| `time.time()` on separate machines | `CLOCK_MONOTONIC` shared by all containers |
| Packet sizes from decrypted inner messages | Sizes logged at DNS, stream and UDP layers, plus pcaps |
| Proxy forwarded to any host:port | Allowlist (`--allow`) |
| Proxy file did not run (`TabError`) | Linted; tested end to end |

Exact ODoQ overhead over DoQ with this format (see `src/odoq/crypto.py`):
request = len(host) + |RSA ciphertext| + 66 bytes (= 331 B for a 9-character host and RSA-2048),
response = 44 bytes.

## Topology

```
client 10.77.1.10 --link_cp-- 10.77.1.20 proxy 10.77.2.20 --link_pr-- 10.77.2.30 resolver
client 10.77.3.10 ----------------------link_cr---------------------- 10.77.3.30 resolver (DoQ)
resolver 10.77.4.30 --link_ra-- 10.77.4.40 auth (NSD)
```

- `resolver` runs Unbound (127.0.0.1:5353) plus the Python frontend: DoQ on 853, ODoQ target on 8853.
- `proxy` listens on 8853 `persistent`, 8854 `per-query` and 8855 `legacy`.
- Each link is an isolated Docker bridge with a fixed host name (`odq-cp`, `odq-pr`, `odq-cr`, `odq-ra`).
  The bridges are internal, so no traffic leaves the testbed.
- CPU pinning: client on core 8 (CPUs 8,24), proxy 9 (9,25), resolver 10 (10,26), auth 11 (11,27),
  tcpdump 13 (13,29). Cores 0–7 are left to the OS, minikube and the routers.

## Running it on the measurement server

Do everything inside tmux (`tmux new -s exp`) so a VPN drop does not kill a run.

```bash
# 0. The folder is already a git repo with one commit. Commit every code or
#    config change BEFORE a campaign: the manifest records the commit and
#    flags uncommitted changes.

# 0b. Once: capture helper (passwordless sudo for exactly one capture command
#     and `virsh list`), so multi-hour campaigns keep capturing
scripts/install_capture_helper.sh

# 1. Before each session
scripts/pause_vms.sh          # pauses only our lab VMs; natrtr/vpnrtr keep running
scripts/host_prep.sh          # netem module, CPU governor = performance

# 2. Build, start, sanity check, smoke campaign, analysis (~10-15 min)
scripts/smoke.sh

# 3. Main campaign (check the plan first, then run; many hours)
python3 tools/run_campaign.py campaigns/stage1_main.json --dry-run
python3 tools/run_campaign.py campaigns/stage1_main.json
python3 tools/analyze.py results/stage1_main_<stamp>

# 4. After the session
docker compose down
scripts/host_restore.sh
scripts/resume_vms.sh
```

Captures go through `/usr/local/sbin/odoq-capture`, which can only capture on the four
testbed bridges, pins tcpdump to CPUs 13,29 and drops to your user before writing. Remove it
after the project with `sudo rm /usr/local/sbin/odoq-capture /etc/sudoers.d/odoq-capture`.

To copy results to the laptop (from WSL Ubuntu):
`rsync -avz user@<server>:~/odoq-testbed/results/ ./results/`

## Campaign factors

| Factor | Values | Meaning |
|---|---|---|
| `variant` | `doq`, `odoq-persistent`, `odoq-per-query`, `odoq-legacy` | protocol and proxy upstream mode |
| `conn_mode` | `warm`, `cold`, `resume` | reuse one connection / new connection per query / new connection with session ticket and 0-RTT |
| `cache` | `hit`, `miss` | `hit` runs one untimed query per domain first; `miss` prefixes a random label so every query misses Unbound's cache (wildcards in the zones keep the answer shape the same) |
| `netem` | profiles in `config/netem_profiles.json` | RTT per link (half applied on each end), loss and jitter per direction |
| `padding` | `none`, `rfc8467` | queries padded to 128 B; the resolver then pads responses to 468 B (RFC 8467 policy) |

The order is blocked-randomized: each repetition visits the netem profiles in random order and
runs every cell of that profile in random order. The proxy is restarted at every profile change
and Unbound's cache is flushed before every run.

## Outputs

```
results/
  components/proxy.jsonl, resolver.jsonl   continuous component logs
  keys/*.keys                              TLS key logs (testbed keys only)
  <campaign>_<stamp>/
    manifest.json   host, kernel, CPU, governor, VM states, image id, pip freeze,
                    Unbound/NSD versions, git commit and dirty state, src hashes,
                    copies of every config (written at start, updated at end)
    plan.json       every run in execution order
    runs.jsonl      per run: factors, seed, monotonic time window, load, netem state
    runs/<id>/      client.jsonl, client.keys, odq-cp/pr/cr/ra.pcap
    queries.csv, summary.csv, breakdown.csv    (after analyze.py)
```

To decrypt captures in Wireshark, load `runs/<id>/client.keys`, `results/keys/proxy.keys` and
`results/keys/resolver.keys` under Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
(merge them into one file).

## Reading the breakdown

`breakdown.csv` gives median milliseconds per stage, from joining client, proxy and resolver logs
on (port, stream id) inside each run's window:

- `c_build`, `c_connect`, `c_open`: client query construction (including RSA-OAEP), connection setup (cold/resume only), response decryption and validation.
- `net_c_to_p`, `net_p_to_r`, `net_r_to_p`, `net_p_to_c` (ODoQ) and `net_c_to_r`, `net_r_to_c` (DoQ): from the sender's timestamp just before `transmit()` to the receiver having the complete message. These include both QUIC stacks' packet processing, not only wire time.
- `p_split`, `p_up_connect`, `p_relay`, `p_legacy_close_wait`: proxy parsing, upstream connection setup (per-query and legacy only), relaying, and in legacy mode the closing-period wait.
- `r_open`, `r_backend`, `r_seal`, `r_send`: resolver decryption, Unbound lookup, encryption, send.

## Things to state in the paper

- Zones are synthetic (`config/domains.json`): the same 10 names as before, with illustrative record counts and documentation-range addresses. Response sizes reflect these zones, not live answers.
- In the netem profiles `cr = cp`, so the proxy is as far from the client as the resolver is (proxy off-path, worst case for ODoQ).
- Cache-miss queries carry an extra 11-byte label, so DNS sizes are slightly larger in `miss` cells; compare sizes in `hit` cells.
- The testbed is an emulated network on one host; a wide-area validation is planned for stage 2.

## Status of testing

Tested in a sandbox on Ubuntu 24.04, Python 3.12.3, Unbound 1.19.2, NSD 4.8.0, aioquic 1.3.0, with all
components on loopback: all variants × connection modes × cache modes, padding, 0-RTT acceptance,
per-hop joins and the analysis tools. Not tested there (no Docker or netem in the sandbox):
the containers, netem shaping, tcpdump capture and the runner's container commands. `scripts/smoke.sh`
is the first test of those on the server.

Sandbox loopback reference (warm, cache hit, no added delay): DoQ ~1.8 ms, ODoQ persistent ~5–7 ms,
ODoQ legacy ~108 ms, of which ~94 ms is the closing-period wait and ~7–9 ms the per-query upstream
handshake. That reproduces the latency pattern in the rejected submission.

## Stage 2: ODoH

ODoH (RFC 9230) runs on the same testbed as a third protocol, via two new
containers on two new shaped links:

  client --link_co-- odoh-relay --link_ot-- odoh-target --link_ra-- auth

- `odoh-target` terminates HPKE (P-256 / AES-128-GCM, same AEAD as ODoQ so the
  comparison isolates key transport) and resolves via its own Unbound.
- `odoh-relay` forwards the opaque ODoH message to the target over HTTP/3,
  reusing one upstream connection, and never sees plaintext.
- Transport is HTTP/3 (`odoh-h3`). The `co`/`ot` links mirror `cp`/`pr`, so
  ODoH and ODoQ both pay two equally-shaped hops.

Measured overhead vs raw DNS (self-test in `src/odoq/odoh.py`):
request 87 B, response 32 B, HPKE encapsulated key 65 B, against ODoQ's
332 B request / 44 B response / 256 B RSA key. ODoH is the smaller on the wire.

Run `odoh-h3` through the same runner, analyzer and plots as the other
variants. Per-hop breakdown for ODoH is not joined in analyze.py yet (its hop
logs are in odoh-relay.jsonl / odoh-target.jsonl); per-query latency, sizes,
CDFs and the sanity check all work.

### ODoH over HTTP/2 (`odoh-h2`)

The ODoH relay and target serve HTTP/3 on UDP and HTTP/2 over TLS 1.3/TCP on the
same port number. A relay reached over HTTP/2 forwards to the target over HTTP/2,
so each ODoH variant uses one transport end to end:

| variant  | client-relay | relay-target | 0-RTT resume |
|----------|--------------|--------------|--------------|
| odoh-h3  | HTTP/3, QUIC | HTTP/3, QUIC | yes          |
| odoh-h2  | HTTP/2, TCP  | HTTP/2, TCP  | not run      |

`odoh-h2` has no `resume` cells: Python's `ssl` module has no TLS early data,
and TLS 1.3 resumption without early data saves no round trips. For `odoh-h2`
the logged `udp_sent_bytes`/`udp_recv_bytes` are HTTP/2 frame bytes (field
`bytes_layer = "h2-frames"`), not TCP/TLS wire bytes; use the pcaps when
comparing on-wire sizes against QUIC.

Campaign: `campaigns/stage2_main.json` (DoQ, ODoQ persistent, ODoH/H3, ODoH/H2;
same sizes and profiles as the executed stage-1 run).
