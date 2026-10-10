# UDPcheck

UDPcheck shows whether your ISP drops inbound UDP from abroad, in which direction (your packets going out, or the replies coming back), and gives you evidence to show to your ISP's support.
Running instance: https://dagart.xyz/en/ (English) and https://dagart.xyz (Russian). [Русская версия](README.ru.md)

## How it works

- **Hub** (`udpcheck_v2.py`, hub role): receives checks, keeps them in SQLite, serves the site, the provider list, the journal and the API.
- **Anchor servers** (same code, target role): answer the browser's UDP requests (STUN) and the nodes' signed UDP echo, and trace the route to a visitor when the hub asks.
  They are needed in the visitor's country (control) and abroad.
- **Nodes** (`udpcheck_node.py`): an agent for home computers, routers and VPS. Every few minutes it sends a UDP stream to the anchor servers and reports the outcome to the hub.
  The "volunteer anchor server" role (`--role ref`) answers other people's checks.
- **Site** (`siteparts/index.tpl.html` plus the texts in `siteparts/strings.py`; `python build_site.py` builds `site/` in Russian and `site/en/` in English):
  a browser check over WebRTC, a provider list with search, a journal and a ready-made text for your ISP's support.

Details: [PROTOCOL.md](PROTOCOL.md). One-line node install: `curl -fsSL https://dagart.xyz/install-node.sh | sudo sh`.

## Principles

- Python 3.10+ standard library only, one file per role, no dependencies.
- The server writes no logs. Visitors' IP addresses live in memory and are erased on a timer; the database keeps only the network (ASN), the result and a random browser number as a hash.
- Long replies and traceroutes go only to the address of a visitor whom the hub has confirmed over TCP (protection against traffic amplification).
- Individuals registered as network owners are never named publicly.

## Directories

| Path | What is there |
|---|---|
| `udpcheck_server.py` | server: STUN, UDP echo, traceroute, GeoIP |
| `udpcheck_v2.py` | hub and the target role |
| `udpcheck_node.py` | node agent |
| `installer/`, `build_site.py`, `siteparts/` | agent installer, building `site/` (page template and texts in two languages) |
| `site/` | built pages (`/`, `/en/`), diagnostics script, protocol documentation |
| `ops/` | server-side scripts: backups, GeoIP updates, watcher and alerts, hardening, tarpit for robots |
| `LICENSE`, `NOTICE`, `PRIVACY-PRINCIPLES.md`, `SECURITY.md`, `CONTRIBUTING.md` | licence, third-party data, privacy principles, vulnerabilities, how to help |
| `docs/SELF-HOSTING.md` | how to run your own hub, anchor servers and nodes |
| `tests/` | tests |
| `add_target.py`, `add_logo.py` | connecting an anchor server, a provider logo |

## Running the tests

```
python tests/test_v2_local.py
python tests/test_refs_local.py
python tests/test_pad_local.py
python tests/test_watch_local.py
python tests/names_selftest.py
python tests/test_s3_local.py
python tests/fuzz_local.py
python tests/test_tarpit_local.py
sh tests/i18n/run.sh          # the interface in Russian and English (needs Docker)
```

You need Python 3.10+ and (for some tests) `traceroute`; on Windows a stub from `tests/` is used.
For real browsers: `tests/browsers_docker.py` (Playwright in Docker).

## Translating the site

All interface texts are in `siteparts/strings.py` (the Russian text is checked against the reference `tests/i18n/golden_ru.json`).
To add a language, add its dictionaries there, a page in `siteparts/pages.py` and the `/<lang>/` routes in `Caddyfile.dagart`.

## Data and licences

- IP geolocation: DB-IP.com (CC BY 4.0). City names: GeoNames (CC BY 4.0). Network names and types: RIPEstat and PeeringDB.
- Provider logos belong to their owners and are shown only as an identifying mark of the network.

## Contact

draldrean@protonmail.com

## Licence, name and domain

The code is distributed under the **GNU AGPL-3.0-or-later** ([LICENSE](LICENSE)). Improve it and run your own copies; if you run a modified version as a service for other people, they are entitled to its source code
(so a visitor can check that the copy does not send their data further than the site). More about what we take from visitors and how: [PRIVACY-PRINCIPLES.md](PRIVACY-PRINCIPLES.md).

The name "UDPcheck" and the domain dagart.xyz belong to the official instance: please give copies and modified versions another name (see [NOTICE](NOTICE)).
How to help: [CONTRIBUTING.md](CONTRIBUTING.md), conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Your own hub: [docs/SELF-HOSTING.md](docs/SELF-HOSTING.md). Vulnerabilities: [SECURITY.md](SECURITY.md).
