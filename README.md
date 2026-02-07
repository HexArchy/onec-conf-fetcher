# onec-conf-fetcher

NetExec module for collecting and parsing 1C Enterprise configuration files from Windows targets via SMB.

## Features

- Collects 6 types of 1C config files from user profiles
- Parses `ibases.v8i`: server-based (`Srvr`/`Ref`) and file-based (`File`) databases, version, app
- Parses `1cestart.cfg`: launcher settings (UTF-16-LE)
- Parses `def.usr`: last logged-in 1C username (multi-encoding: utf-8-sig, utf-8, cp1251, utf-16-le)
- Parses `appsrvrs.lst`: application server addresses
- Parses `nethasp.ini`: HASP license server addresses (`NH_SERVER_ADDR`)
- Collects `1cv8conn.pfl` (binary connection profiles, not parsed)
- Detects 1C Application Server installation (`Program Files\1cv8\srvinfo`)
- User enumeration: Windows Registry (admin) with SMB fallback
- Supports both modern (Vista+: `Users`, `AppData\Roaming`) and legacy (XP/2003: `Documents and Settings`, `Application Data`) Windows paths
- Exports per-user files + aggregated `host_summary.json` with database deduplication

## Installation

```bash
cp src/onec_conf_fetcher.py ~/.nxc/modules/
```

## Usage

```bash
# Basic scan
nxc smb <target> -u <user> -p <pass> -M onec_conf_fetcher

# With export
nxc smb <target> -u <user> -p <pass> -M onec_conf_fetcher -o EXPORT=true OUTPUT=/tmp/out

# Subnet scan
nxc smb 192.168.1.0/24 -u admin -p pass -M onec_conf_fetcher -o EXPORT=true
```

> **Note:** Use a single `-o` with space-separated options. Multiple `-o` flags overwrite each other in NXC.

## Module Options

| Option   | Default                        | Description                     |
|----------|--------------------------------|---------------------------------|
| `EXPORT` | `false`                        | Export collected files to disk   |
| `OUTPUT` | `~/.nxc/onec_conf_fetcher/`    | Custom output directory          |

## Collected Files

| File           | Relative Path                        | Content                        |
|----------------|--------------------------------------|--------------------------------|
| `ibases.v8i`   | `1C\1CEStart\ibases.v8i`             | Database connections           |
| `1cestart.cfg` | `1C\1CEStart\1cestart.cfg`           | Launcher settings              |
| `def.usr`      | `1C\1cv8\def.usr`                    | Last 1C username               |
| `1cv8conn.pfl` | `1C\1cv8\1cv8conn.pfl`              | Connection profiles (binary)   |
| `appsrvrs.lst` | `1C\1cv8\appsrvrs.lst`              | Application servers            |
| `nethasp.ini`  | `1C\1cv8\conf\nethasp.ini`          | HASP license server config     |

Paths are resolved under `%APPDATA%` (`AppData\Roaming` on Vista+, `Application Data` on XP/2003).

## Export Structure

```
OUTPUT/
  <host_ip>/
    host_summary.json        # aggregated summary
    <username>/
      ibases.v8i
      1cestart.cfg
      ...
    _server_/                # server-side configs (if detected)
      server_nethasp.ini
```

## host_summary.json

Contains:
- Host info (IP, hostname, domain)
- All enumerated users and which have 1C configs
- Unique databases (server-based and file-based) with user mapping
- Unique 1C server addresses
- Last 1C usernames per Windows user
- License server addresses
- Launcher settings and app server lists
- 1C Application Server detection flag

## Requirements

- Python 3.12+
- NetExec
- impacket >= 0.12.0

## License

MIT
