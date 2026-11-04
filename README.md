# ShadowPort

[![Python](https://img.shields.io/badge/python-3.6+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Category](https://img.shields.io/badge/recon-port%20scanning-C7547F.svg)](#)

> Port scanning and service enumeration with banner grabbing, DNS reconnaissance and tunable scan speed — with HTML and JSON reporting.

ShadowPort is a footprinting tool for the recon phase of an authorized assessment: it sweeps a port range on a target, fingerprints the services it finds, grabs banners, enumerates DNS, and writes a report you can drop into an engagement. Scan speed is tunable so you can stay gentle on fragile targets or move fast in a lab.

## Features

- **Port scanning** — configurable ranges with `slow` / `medium` / `fast` profiles
- **Service detection** — fingerprinting and banner grabbing
- **DNS enumeration** — reconnaissance around the target domain
- **Aggressive mode** — deeper enumeration when authorized
- **Reports** — HTML and JSON, with custom output names
- **Resilient** — clean handling of interrupts and errors

## Install

```bash
git clone https://github.com/CHDevSec/ShadowPort.git
cd ShadowPort
pip install -r requirements.txt
```

## Usage

```bash
python3 ShadowPort.py -t <target> [options]
```

| Option | Description |
|---|---|
| `-t, --target` | Target IP or domain (required) |
| `--range 1-1000` | Port range |
| `--speed {slow,medium,fast}` | Scan speed (default `medium`) |
| `--aggressive` | Enable aggressive enumeration |
| `--html` / `--json` | Report format |
| `--output-name NAME` | Custom output file name |
| `--verbose` | Show execution details |

### Example

```bash
python3 ShadowPort.py -t target.local --range 1-65535 --speed fast --html --verbose
```

## Legal & ethical use

This tool is intended for **authorized security testing and education only**. Use it exclusively against systems you own or have **explicit written permission** to assess. The author assumes no liability for misuse or for any damage caused by this software. You are responsible for complying with all applicable laws.

## License

[MIT](LICENSE) © 2025-2026 Caio Henrique ([CHDevSec](https://github.com/CHDevSec))

<sub>Part of the CHDevSec security tooling — <a href="https://chdevsec.com.br/portfolio/">portfolio</a> · <a href="https://www.linkedin.com/in/caio-henrique-security">LinkedIn</a></sub>
