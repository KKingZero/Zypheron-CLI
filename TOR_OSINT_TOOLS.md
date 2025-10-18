# TOR/OSINT Tools Integration Guide

This guide provides recommended free and open-source tools for enhancing COBRA AI's penetration testing capabilities with TOR anonymity and OSINT intelligence gathering.

## TOR Integration

### 1. **TOR Proxy Setup**

#### Linux (Kali)
```bash
# Install TOR
sudo apt install tor torsocks proxychains

# Configure proxychains
sudo nano /etc/proxychains.conf
# Add: socks5 127.0.0.1 9050
```

#### Windows
- **TOR Expert Bundle**: https://www.torproject.org/download/tor/
- **Privoxy**: http://www.privoxy.org/ (HTTP proxy for TOR)

#### Web Integration
```javascript
// Use SOCKS proxy in Node.js
const SocksProxyAgent = require('socks-proxy-agent');
const agent = new SocksProxyAgent('socks5://127.0.0.1:9050');
```

## OSINT Tools (Free & Open Source)

### 1. **Subdomain Enumeration**

#### **Amass** (Best Overall)
- **Platform**: Linux, Windows, macOS
- **Installation**: `go install -v github.com/owasp/amass/v3/...@master`
- **Features**: DNS enumeration, web scraping, API integration
- **Usage**: `amass enum -d example.com`

#### **Sublist3r**
- **Platform**: Linux, Windows, macOS  
- **Installation**: `git clone https://github.com/aboul3la/Sublist3r.git`
- **Features**: Search engine scraping, bruteforce
- **Usage**: `python sublist3r.py -d example.com`

#### **Subfinder** 
- **Platform**: Linux, Windows, macOS
- **Installation**: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
- **Features**: Fast passive subdomain discovery
- **Usage**: `subfinder -d example.com`

### 2. **Port Scanning & Service Detection**

#### **Nmap**
- **Platform**: Linux, Windows, macOS
- **Installation**: 
  - Linux: `sudo apt install nmap`
  - Windows: Download from nmap.org
- **TOR Usage**: `proxychains nmap -sT -Pn target.com`
- **Features**: Comprehensive port scanning, service detection

#### **Masscan**
- **Platform**: Linux, Windows
- **Installation**: `sudo apt install masscan`
- **Features**: Ultra-fast port scanning
- **Usage**: `masscan -p1-65535 target.com --rate=1000`

#### **RustScan**
- **Platform**: Linux, Windows, macOS
- **Installation**: `cargo install rustscan`
- **Features**: Fast modern scanner
- **Usage**: `rustscan -a target.com`

### 3. **Directory & File Discovery**

#### **Gobuster**
- **Platform**: Linux, Windows, macOS
- **Installation**: `go install github.com/OJ/gobuster/v3@latest`
- **Features**: Fast directory/file bruteforcer
- **Usage**: `gobuster dir -u https://example.com -w wordlist.txt`

#### **Feroxbuster** 
- **Platform**: Linux, Windows, macOS
- **Installation**: `cargo install feroxbuster`
- **Features**: Recursive content discovery
- **Usage**: `feroxbuster -u https://example.com`

#### **Dirsearch**
- **Platform**: Linux, Windows, macOS
- **Installation**: `git clone https://github.com/maurosoria/dirsearch.git`
- **Features**: Web path scanner
- **Usage**: `python3 dirsearch.py -u https://example.com`

### 4. **OSINT Intelligence Gathering**

#### **theHarvester**
- **Platform**: Linux, Windows, macOS
- **Installation**: `git clone https://github.com/laramies/theHarvester`
- **Features**: Email, subdomain, IP gathering
- **Usage**: `theHarvester -d example.com -b all`

#### **Recon-ng**
- **Platform**: Linux, Windows, macOS
- **Installation**: `git clone https://github.com/lanmaster53/recon-ng.git`
- **Features**: Full-featured reconnaissance framework
- **Usage**: Interactive shell with modules

#### **SpiderFoot**
- **Platform**: Linux, Windows, macOS
- **Installation**: `git clone https://github.com/smicallef/spiderfoot.git`
- **Features**: Automated OSINT collection
- **Web UI**: `python3 sf.py -l 127.0.0.1:5001`

### 5. **Web Application Analysis**

#### **WhatWeb**
- **Platform**: Linux, Windows, macOS
- **Installation**: `git clone https://github.com/urbanadventurer/WhatWeb.git`
- **Features**: Web technology fingerprinting
- **Usage**: `whatweb example.com`

#### **Wappalyzer CLI**
- **Platform**: Linux, Windows, macOS
- **Installation**: `npm install -g wappalyzer`
- **Features**: Technology stack detection
- **Usage**: `wappalyzer https://example.com`

### 6. **DNS & Network Intelligence**

#### **DNSRecon**
- **Platform**: Linux, Windows, macOS
- **Installation**: `git clone https://github.com/darkoperator/dnsrecon.git`
- **Features**: DNS record enumeration
- **Usage**: `dnsrecon -d example.com`

#### **Fierce**
- **Platform**: Linux, Windows, macOS
- **Installation**: `pip install fierce`
- **Features**: DNS reconnaissance
- **Usage**: `fierce --domain example.com`

## API-Based OSINT Sources (Free Tiers)

### 1. **Shodan**
- **Free Tier**: 100 results/month
- **API**: `pip install shodan`
- **Usage**: 
```python
import shodan
api = shodan.Shodan('YOUR_API_KEY')
results = api.search('hostname:example.com')
```

### 2. **Censys**
- **Free Tier**: 250 queries/month
- **API**: `pip install censys`
- **Features**: Certificate transparency, host data

### 3. **VirusTotal**
- **Free Tier**: 500 requests/day
- **API**: Public API available
- **Features**: Domain reputation, URL scanning

## Integration Example

### Combining Tools with TOR
```bash
#!/bin/bash
# TOR-enabled OSINT scan

# Start TOR
sudo service tor start

# Subdomain enumeration via TOR
proxychains amass enum -d $TARGET

# Port scan via TOR (slow but anonymous)  
proxychains nmap -sT -Pn -top-ports 100 $TARGET

# Directory enumeration via TOR
proxychains gobuster dir -u https://$TARGET -w /usr/share/wordlists/dirb/common.txt
```

### Python Integration
```python
import subprocess
import requests
from stem import Signal
from stem.control import Controller

# Rotate TOR IP
def rotate_tor_ip():
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)

# Make request through TOR
def tor_request(url):
    proxies = {
        'http': 'socks5://127.0.0.1:9050',
        'https': 'socks5://127.0.0.1:9050'
    }
    return requests.get(url, proxies=proxies)
```

## Recommended Workflows

### 1. **Passive Reconnaissance**
1. **theHarvester** - Initial OSINT gathering
2. **Amass** - Comprehensive subdomain enumeration
3. **Shodan/Censys API** - Existing scan data

### 2. **Active Scanning (with TOR)**
1. **Subfinder** → **DNSRecon** - DNS intelligence
2. **RustScan** → **Nmap** - Port discovery and service detection
3. **Feroxbuster** - Content discovery

### 3. **Responsible Scanning**
- Use rate limiting: `--rate-limit` flags
- Respect robots.txt
- Use TOR for anonymity but expect slower speeds
- Rotate IPs between scans
- Cache results to avoid repeated queries

## Best Practices

1. **Rate Limiting**
   - Amass: `amass enum -d target.com -rf 5`
   - Gobuster: `gobuster dir -u target -t 10 --delay 100ms`

2. **Wordlist Selection**
   - Small: `/usr/share/wordlists/dirb/small.txt`
   - Medium: `/usr/share/wordlists/dirb/common.txt`
   - Large: `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`

3. **Output Formats**
   - JSON for parsing: `-o output.json -oJ`
   - CSV for reports: `-o output.csv -oC`

## Tool Selection Matrix

| Task | Web-Based | Linux (Best) | Windows | TOR Compatible |
|------|-----------|--------------|---------|----------------|
| Subdomains | BuiltWith | Amass | Sublist3r | ✅ (Slow) |
| Ports | Shodan | Nmap | Nmap | ✅ (TCP only) |
| Directories | - | Gobuster | Dirsearch | ✅ |
| OSINT | SpiderFoot | theHarvester | SpiderFoot | ✅ |
| DNS | ViewDNS | DNSRecon | Fierce | ✅ |

## Security Considerations

1. **Legal**: Always have permission before scanning
2. **Attribution**: TOR provides anonymity but not immunity
3. **Performance**: TOR significantly slows scans
4. **Detection**: Even with TOR, aggressive scanning patterns can be detected
5. **Ethics**: Use findings responsibly for security improvement

## Future Enhancements

1. **Integrate Nuclei** for vulnerability scanning
2. **Add Metasploit** integration for exploitation
3. **Implement rotating proxy chains**
4. **Add blockchain OSINT tools**
5. **Integrate dark web monitoring**

Remember: These tools are powerful and should only be used on systems you own or have explicit permission to test. 