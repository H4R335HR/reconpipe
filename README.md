# recon

Automated bug bounty recon pipeline. Chains subdomain enumeration, DNS resolution, HTTP probing, port scanning, URL discovery, and vulnerability scanning into a single command.

```
subfinder → dnsx → httpx + naabu → gau + katana + ffuf → nuclei
```

## Install

```bash
cp recon.sh ~/.local/bin/recon
chmod +x ~/.local/bin/recon
```

## Usage

```bash
recon -d target.com
recon -d target.com -w /path/to/wordlist.txt
recon -d target.com -p 500 -c 80 --skip-ffuf
```

| Flag | Description | Default |
|------|-------------|---------|
| `-d` | Target domain (required) | — |
| `-w` | Wordlist for ffuf | auto-detect |
| `-p` | Top N ports for naabu | 1000 |
| `-c` | Concurrency / threads | 50 |
| `-k` | Katana crawl depth | 3 |
| `-s` | Nuclei severity filter | low,medium,high,critical |
| `--skip-ffuf` | Skip directory brute-forcing | false |

## Output

All results saved to `./recon/<domain>/<timestamp>/`:

```
├── subdomains/          # subfinder output
├── dns/                 # resolved hosts, CNAMEs
├── httpx/               # alive hosts (standard + all ports)
├── ports/               # naabu open ports
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
5. **gau** collects historical URLs, **katana** crawls live targets, **ffuf** brute-forces directories
6. All URLs merged and categorized
7. **nuclei** scans hosts, URLs, parameterized endpoints, and CNAMEs separately
8. **gowitness** screenshots alive hosts (if installed)
9. **notify** sends findings to Slack/Discord/Telegram (if configured)

## License

MIT
