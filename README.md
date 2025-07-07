# VMS
🔧 Core Features:

ZSH + Oh My Zsh with useful plugins and themes
Complete directory structure for organized work
All major programming languages (Python, Go, Node.js, Ruby, Java, PHP, Rust, Perl)
Docker setup with vulnerable applications for testing

🛠️ Bug Bounty Tools:

Subdomain enumeration: subfinder, assetfinder, amass, sublist3r
Web scanning: nmap, masscan, gobuster, dirb, nikto
Web app testing: burpsuite, zaproxy, sqlmap, xsstrike
OSINT tools: theharvester, sherlock, spiderfoot
Cloud security: ScoutSuite, S3Scanner
Mobile security: MobSF, objection

📁 Directory Structure:

~/tools/ - All GitHub cloned tools
~/scripts/ - Custom automation scripts
~/wordlists/ - SecLists and other wordlists
~/go/bin/ - Go tools

🚀 Automation Scripts:

Reconnaissance script (recon.sh) - Automated subdomain enum and scanning
XSS testing script (xss_test.sh) - Automated XSS detection
SQL injection script (sqli_test.sh) - Automated SQLi testing
Useful aliases for quick commands

💡 Usage:
```
chmod +x setup_kali.sh
```

Run it: ./setup_kali.sh
Follow the prompts for Git configuration
Log out and back in to apply ZSH

⚠️ Important Notes:

Run as regular user (not root) for security
Some tools may need API keys (Shodan, SecurityTrails, etc.)
The script will take time to complete (30-60 minutes)
Internet connection required for downloads

🔐 Anonymity & VPN Features:
VPN Solutions:

ProtonVPN CLI - Professional VPN with CLI management
OpenVPN & WireGuard - Multiple VPN protocol support
Tor integration - Complete Tor setup with proper configuration
AnonSurf & Kalitorify - System-wide anonymization tools

Traffic Management:

ProxyChains4 - Route traffic through proxy chains
IP Rotation - Automated IP rotation and validation
MAC Address Randomization - Automatic network adapter spoofing
DNS over HTTPS - Encrypted DNS queries via Cloudflared

VirtualBox-Specific Security:

Guest Additions warnings - Prevents host information leakage
Network configuration - NAT-only setup recommendations
Snapshot automation - Security workflow with VM snapshots
Hardware fingerprinting - Disable identifying hardware features

🛠️ Key Scripts Added:

vpn_manager.sh - Interactive VPN/Tor management interface
ip_rotator.sh - Automated IP rotation and anonymity validation
anon_recon.sh - Anonymous reconnaissance with proxy support
traffic_analysis.py - Traffic pattern analysis and evasion
vbox_anon_setup.sh - VirtualBox-specific anonymity configuration
privacy_hardening.sh - Comprehensive system hardening

🚀 Anonymity Workflow:

Take VM snapshot before operations
Start VPN/Tor using the management script
Rotate IP and MAC addresses
Validate anonymity with built-in checks
Run reconnaissance through proxies
Clear all traces automatically
Restore snapshot to clean state

⚠️ Critical VirtualBox Security:

Never install Guest Additions (leaks host information)
Use NAT networking only (never Bridged mode)
Disable all sharing features (folders, clipboard, USB)
Regular MAC randomization and hostname changes
Snapshot-based operations for maximum security

🔄 Automated Features:

Startup MAC randomization on boot
Automatic log cleaning daily
DNS leak prevention with DoH
Kernel hardening for privacy
Browser fingerprinting protection
