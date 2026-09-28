# reconpipe

Automated bug bounty recon pipeline. Chains subdomain enumeration, DNS resolution, HTTP probing, port scanning, URL discovery, and vulnerability scanning into a single command.

```
subfinder → dnsx → httpx + naabu → vhost discovery → gau + katana + ffuf → nuclei
```

## Install

```bash
cp reconpipe.sh ~/.local/bin/reconpipe
chmod +x ~/.local/bin/reconpipe
```

## Usage

```bash
reconpipe -d target.com
reconpipe -d target.com -w /path/to/wordlist.txt
reconpipe -d target.com -p 500 -c 80 --skip-ffuf
reconpipe -d target.com --enable-vhosts          # force vhost scan even if subdomains exist
reconpipe -d target.com -V /path/to/subdomains.txt  # custom vhost wordlist
```

| Flag | Description | Default |
|------|-------------|---------|
| `-d` | Target domain (required) | — |
| `-w` | Wordlist for ffuf | auto-detect |
| `-V` | Wordlist for vhost discovery | auto-detect (SecLists) |
| `-p` | Top N ports for naabu | 1000 |
| `-c` | Concurrency / threads | 50 |
| `-k` | Katana crawl depth | 3 |
| `-s` | Nuclei severity filter | low,medium,high,critical |
| `--skip-ffuf` | Skip directory brute-forcing | false |
| `--enable-vhosts` | Force vhost discovery | auto (enabled when no subdomains found) |
| `--nuclei-urls` | Also scan all URLs with nuclei | false |
| `--nuclei-params` | Also scan parameterized URLs with nuclei | false |
| `--nuclei-full` | Enable both `--nuclei-urls` and `--nuclei-params` | false |
| `--resume` | Resume the most recent incomplete run | false |

## Output

All results saved to `./reconpipe/<domain>/<timestamp>/`:

```
├── subdomains/          # subfinder output
├── dns/                 # resolved hosts, CNAMEs
├── httpx/               # alive hosts (standard + all ports)
├── ports/               # naabu open ports
├── vhosts/              # discovered virtual hosts
├── urls/                # gau + katana + ffuf merged, categorized
├── fuzzing/             # ffuf results per host
├── vulnerabilities/     # nuclei findings
├── screenshots/         # gowitness captures
├── logs/                # per-tool error logs
└── REPORT.md            # summary with counts
```

URLs are auto-categorized into JS files, config files, dynamic endpoints, and parameterized URLs for targeted follow-up.

## Requirements

**Required:** subfinder, dnsx, httpx, naabu, gau, katana, nuclei

**Optional:** ffuf, gowitness, notify, anew

**Wordlists:** [SecLists](https://github.com/danielmiessler/SecLists) — required for vhost discovery and used as a fallback for ffuf directory brute-forcing. The script auto-detects wordlists from standard install paths (`/usr/share/seclists/`, `/opt/SecLists/`).

```bash
# Kali / Debian
sudo apt install seclists

# Manual
git clone https://github.com/danielmiessler/SecLists.git /opt/SecLists
```

On Kali, `httpx-toolkit` is auto-detected (avoids the Python httpx conflict).

Install all ProjectDiscovery tools:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/tomnomnom/anew@latest
```

## How it works

1. **subfinder** enumerates subdomains passively
2. **dnsx** resolves DNS, filters dead hosts, flags CNAMEs for takeover
3. **httpx** probes alive HTTP services on standard ports
4. **naabu** port scans, then **httpx** probes again on all discovered ports
5. **vhost discovery** — if subfinder found zero subdomains, **ffuf** brute-forces `Host:` headers against alive origins to find virtual hosts that have no DNS records. Discovered vhosts are merged into the alive list for downstream phases. Use `--enable-vhosts` to force this on even when subdomains exist
6. **gau** collects historical URLs, **katana** crawls live targets, **ffuf** brute-forces directories
7. All URLs merged and categorized
8. **nuclei** scans hosts, URLs, parameterized endpoints, and CNAMEs separately
9. **gowitness** screenshots alive hosts (if installed)
10. **notify** sends findings to Slack/Discord/Telegram (if configured)

## License

MIT
