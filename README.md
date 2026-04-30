> **Legal notice:** This tool is for authorised penetration testing, CTF platforms (HackTheBox, TryHackMe), and your own lab environments only. Running it against systems you do not have explicit written permission to test is illegal. The authors accept no liability for misuse.

---

# Kali MCP

Connect Claude, GitHub Copilot, or any MCP-compatible AI agent to a live Kali Linux machine. Talk to your tools in plain English — the agent picks the right binary, chains the results, and hands you a structured report.

```
"Scan 10.10.11.5 and tell me what's worth attacking"
  → nmap → whatweb → nikto → gobuster → structured report

"I got SSH creds as www-data — escalate to root"
  → ssh_command → run_linpeas → searchsploit → sudo abuse → root.txt
```

The full post-exploitation loop closes: enumerate → exploit → shell → privesc → flag. No copy-pasting between tools, no tab-switching, no waiting around.

---

## How it works

```
AI Agent (Claude / Copilot / Claude Code)
        │
        │  MCP protocol  (stdio)
        ▼
   client.py      ─── FastMCP server, exposes tools / resources / prompts
        │
        │  HTTP  (localhost:5000)
        ▼
   server.py      ─── Flask REST API
        │
        │  subprocess / paramiko
        ▼
   Kali binaries  ─── nmap, tshark, sqlmap, metasploit, ssh ...
```

Two processes run at all times:

| Process    | File        | Role                                                |
|------------|-------------|-----------------------------------------------------|
| Flask API  | `server.py` | Executes real Kali binaries, exposes REST endpoints |
| MCP server | `client.py` | Bridges the AI agent to Flask via MCP stdio         |

---

## Project structure

```
~/Kali-MCP/
├── client.py                  ← MCP entry point (launched by the AI host)
├── server.py                  ← Flask entry point (run as a systemd service)
├── client/
│   ├── safety.py              ← Prompt injection guardrails
│   ├── http_client.py         ← HTTP wrapper around Flask
│   ├── tools.py               ← 32 @mcp.tool definitions
│   ├── resources.py           ← 9 @mcp.resource read-only data sources
│   └── prompts.py             ← 9 @mcp.prompt workflow playbooks
└── server/
    ├── executor.py            ← Subprocess management
    ├── routes_tools.py        ← Blueprint: /api/tools/*
    └── routes_system.py       ← Blueprint: /api/command, /health
```

---

## Installation

### System dependencies

```bash
sudo apt update && sudo apt install -y \
  nmap masscan netdiscover \
  gobuster dirb ffuf nikto sqlmap whatweb wpscan \
  hydra john hashcat \
  tshark tcpdump \
  metasploit-framework exploitdb \
  enum4linux smbclient \
  ncat rlwrap peass \
  netexec
```

### Python — Option A: pip

```bash
cd ~/Kali-MCP
pip install flask requests "mcp[cli]" paramiko --break-system-packages
```

### Python — Option B: uv (recommended)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh && source ~/.bashrc
cd ~/Kali-MCP
uv venv && source .venv/bin/activate
uv pip install flask requests "mcp[cli]" paramiko
```

> When using uv, replace `python3` with `/home/kali/Kali-MCP/.venv/bin/python3` in the systemd service and MCP config files below.

### Verify

```bash
python3 server.py
# → Starting Kali Linux Tools API Server on 127.0.0.1:5000

curl http://localhost:5000/health
# → {"status": "healthy", ...}
```

---

## Run on startup (systemd)

```bash
sudo nano /etc/systemd/system/kali-mcp.service
```

```ini
[Unit]
Description=Kali MCP Flask Server
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/kali/Kali-MCP/server.py
WorkingDirectory=/home/kali/Kali-MCP
Restart=always
RestartSec=3
User=kali

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kali-mcp
sudo systemctl status kali-mcp
```

---

## MCP client setup

### Claude Desktop

Config location:
- Linux: `~/.config/Claude/claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "kali": {
      "command": "python3",
      "args": ["/home/kali/Kali-MCP/client.py"]
    }
  }
}
```

Restart Claude Desktop. A 🔨 icon appears in the chat input when tools are loaded. Resources and prompts work as attachable context and slash commands.

### VS Code + GitHub Copilot

`~/.vscode/mcp.json` or workspace `.vscode/mcp.json`:

```json
{
  "mcp": {
    "servers": {
      "kali": {
        "type": "stdio",
        "command": "python3",
        "args": ["/home/kali/Kali-MCP/client.py"]
      }
    }
  }
}
```

`Ctrl+Shift+P` → **MCP: List Servers** to confirm. Note: Copilot supports tools only — resources and prompts require Claude Desktop or Claude Code.

### Claude Code

`~/.claude.json`:

```json
{
  "mcpServers": {
    "kali": {
      "command": "python3",
      "args": ["/home/kali/Kali-MCP/client.py"],
      "type": "stdio"
    }
  }
}
```

```bash
claude
/tools    # confirm kali tools are listed
/mcp      # check server status
```

---

## Capabilities

### Tools

32 tools across 7 categories. All defined in `client/tools.py`.

#### Scanning & Discovery

| Tool                | Description                             | Key parameters                   |
|---------------------|-----------------------------------------|----------------------------------|
| `nmap_scan`         | Port scanner and service fingerprinter  | `target`, `scan_type`, `ports`   |
| `masscan_scan`      | Fast full-port scanner for large ranges | `target`, `ports`, `rate`        |
| `netdiscover_scan`  | ARP host discovery on a subnet          | `target_range`, `interface`      |

#### Web

| Tool                  | Description                              | Key parameters                          |
|-----------------------|------------------------------------------|-----------------------------------------|
| `gobuster_scan`       | Directory / DNS / vhost brute-forcer     | `url`, `mode`, `wordlist`               |
| `dirb_scan`           | Web content discovery                    | `url`, `wordlist`                       |
| `ffuf_fuzz`           | Fast fuzzer — dirs, params, vhosts       | `url`, `wordlist`, `filter_codes`       |
| `nikto_scan`          | Web server vulnerability scanner         | `target`                                |
| `whatweb_fingerprint` | Technology fingerprinter                 | `url`, `aggression`                     |
| `wpscan_analyze`      | WordPress scanner                        | `url`, `additional_args`                |
| `sqlmap_scan`         | SQL injection tester                     | `url`, `data`                           |
| `http_request`        | Full curl — GET/POST, headers, cookies   | `url`, `method`, `data`, `headers`      |

#### Exploitation

| Tool                | Description                              | Key parameters                             |
|---------------------|------------------------------------------|--------------------------------------------|
| `metasploit_run`    | Metasploit module executor               | `module`, `options`                        |
| `searchsploit`      | Search Exploit-DB offline archive        | `query`                                    |
| `msfvenom_generate` | Generate reverse/bind shell payloads     | `payload`, `lhost`, `lport`, `format`      |
| `start_listener`    | Netcat listener for reverse shells       | `port`, `duration`                         |

#### Credentials

| Tool            | Description                    | Key parameters                                 |
|-----------------|--------------------------------|------------------------------------------------|
| `hydra_attack`  | Online password brute-forcer   | `target`, `service`, `username`, `password_file` |
| `john_crack`    | Offline hash cracker           | `hash_file`, `wordlist`, `format_type`         |
| `hashcat_crack` | GPU-accelerated hash cracking  | `hash_file`, `hash_type`, `wordlist`           |

#### Windows / Active Directory

| Tool                  | Description                               | Key parameters                    |
|-----------------------|-------------------------------------------|-----------------------------------|
| `enum4linux_scan`     | Windows / Samba enumeration               | `target`                          |
| `smbclient_interact`  | Read and download files from SMB shares   | `target`, `share`, `smb_command`  |
| `crackmapexec`        | SMB/AD Swiss army knife                   | `target`, `protocol`, `hash`      |

#### Post-Exploitation

| Tool           | Description                               | Key parameters                           |
|----------------|-------------------------------------------|------------------------------------------|
| `ssh_command`  | Run commands on a remote host over SSH    | `host`, `username`, `command`            |
| `run_linpeas`  | Upload and execute LinPEAS/WinPEAS        | `host`, `username`, `script_type`        |

#### Network / Traffic

| Tool                | Description                             | Key parameters                             |
|---------------------|-----------------------------------------|--------------------------------------------|
| `tshark_capture`    | Live packet capture                     | `interface`, `capture_filter`, `duration`  |
| `tshark_read_pcap`  | Analyse existing .pcap / .pcapng files  | `pcap_file`, `display_filter`              |
| `tcpdump_capture`   | Lightweight packet capture              | `interface`, `capture_filter`              |

#### Utility

| Tool              | Description                            |
|-------------------|----------------------------------------|
| `execute_command` | Run any arbitrary shell command        |
| `server_health`   | Check which tools are installed        |

---

### Resources

Read-only context sources the agent fetches without triggering any real action. Defined in `client/resources.py`.

> Claude Desktop and Claude Code only. Copilot uses the equivalent tool calls instead.

| URI                                    | Description                                      |
|----------------------------------------|--------------------------------------------------|
| `kali://server/health`                 | Live tool availability status                    |
| `kali://server/tools`                  | Full tool catalogue                              |
| `kali://server/wordlists`              | Wordlists present on the Kali server             |
| `kali://server/network`                | Network interfaces and routing table             |
| `kali://methodology/pentest-phases`    | Standard pentest phase reference                 |
| `kali://methodology/common-ports`      | Port → recommended tools lookup                  |
| `kali://methodology/privesc-linux`     | Linux privesc checklist (SUID, sudo, cron, caps) |
| `kali://methodology/privesc-windows`   | Windows privesc checklist (tokens, services, PTH)|
| `kali://methodology/reverse-shells`    | Reverse shell one-liners for every language      |

---

### Prompts

Workflow playbooks that load a full methodology into the agent's context. Defined in `client/prompts.py`.

> Claude Desktop (slash commands) and Claude Code. Not supported in Copilot.

| Prompt              | When to use                        | What it does                                                        |
|---------------------|------------------------------------|---------------------------------------------------------------------|
| `full_recon`        | Start of an engagement             | nmap → service enum → web deep dive → report                        |
| `web_pentest`       | Web application assessment         | Fingerprint → content discovery → CMS detection → injection         |
| `smb_enumeration`   | Ports 139/445 open                 | Shares, users, EternalBlue check                                    |
| `ctf_helper`        | HTB / THM machine                  | Enum → foothold → user flag → privesc → root flag                   |
| `explain_output`    | Interpret raw tool output          | Summary, findings by severity, next steps                           |
| `password_attack`   | Have usernames, need creds         | Wordlist selection → hydra → john → report                          |
| `post_exploitation` | Got a shell, need to escalate      | Situational awareness → linpeas → sudo/SUID/cron → flags            |
| `exploit_search`    | Found a service version            | searchsploit → metasploit module → exploitation                     |
| `active_directory`  | Domain environment                 | Enum → Kerberoasting → AS-REP → pass-the-hash → Domain Admin        |

---

## Usage examples

**Quick scan**
```
"Run nmap on 10.10.11.5"
```

**Full CTF engagement**
```
"Use the ctf_helper prompt on 10.10.11.5"
```

**Post-exploitation**
```
"I have SSH creds admin:Password123 on 10.10.11.5 — use the post_exploitation prompt"
```
Runs automatically: `ssh_command → run_linpeas → searchsploit → escalate → root.txt`

**Payload generation**
```
"Generate a Linux reverse shell for 10.10.14.5:4444 and start a listener"
```

**Pcap analysis**
```
"Read /root/challenge.pcap and find any credentials — filter for FTP and HTTP POST"
```

**Exploit a version**
```
"Use the exploit_search prompt for vsftpd 2.3.4"
```

**Active Directory**
```
"Use the active_directory prompt — DC 10.10.10.175, domain htb.local, creds svc-alfresco:s3rvice"
```

---

## Troubleshooting

**Port 5000 in use**
```bash
sudo fuser -k 5000/tcp && sudo systemctl start kali-mcp
```

**Tools not loading in Copilot**
```
Ctrl+Shift+P → MCP: Restart Server → kali
```

**Flask not reachable**
```bash
curl http://localhost:5000/health
sudo systemctl status kali-mcp
journalctl -u kali-mcp -f
```

**tshark permission denied**
```bash
sudo usermod -aG wireshark kali
# log out and back in
```

**ssh_command / run_linpeas fails**
```bash
pip install paramiko --break-system-packages
```

**LinPEAS not found**
```bash
# apt
sudo apt install peass

# or download directly
wget -O /root/linpeas.sh \
  https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh
```

**crackmapexec not found**
```bash
sudo apt install netexec   # provides nxc — auto-detected by the route
```