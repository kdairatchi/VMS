#!/bin/bash
# Kali Linux Bug Bounty Complete Setup Script
# Author: Kdairatchi
# Description: Comprehensive setup on fresh Kali Linux

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons."
   exit 1
fi

print_info "Starting Kali Linux Bug Bounty Setup..."

# ...existing code...
cat > ~/scripts/sqli_test.sh << 'EOF'
#!/bin/bash
# SQL injection testing script with anonymity
# Usage: ./sqli_test.sh <url> [proxy]

if [ $# -eq 0 ]; then
    echo "Usage: $0 <url> [proxy]"
    echo "Examples:"
    echo "  $0 http://target.com"
    echo "  $0 http://target.com --tor"
    echo "  $0 http://target.com --proxy=socks5://127.0.0.1:9050"
    exit 1
fi

URL=$1
PROXY_ARG=""

if [ "$2" = "--tor" ]; then
    PROXY_ARG="--tor"
    echo "[+] Using Tor for anonymity"
elif [[ "$2" == --proxy=* ]]; then
    PROXY_ARG="$2"
    echo "[+] Using custom proxy: ${2#--proxy=}"
fi

echo "[+] Testing SQL injection on $URL"

# Basic SQLMap scan with proxy
sqlmap -u "$URL" --batch --banner --dbs $PROXY_ARG --random-agent

# Advanced SQLMap scan with proxy
sqlmap -u "$URL" --batch --banner --dbs --tables --columns --dump $PROXY_ARG --random-agent

echo "[+] SQL injection testing complete"
EOF
chmod +x ~/scripts/sqli_test.sh

# Create anonymous reconnaissance script
print_status "Creating anonymous reconnaissance script..."
cat > ~/scripts/anon_recon.sh << 'EOF'
#!/bin/bash
# Anonymous reconnaissance script with VPN/Tor integration
# Usage: ./anon_recon.sh domain.com [--tor|--proxy]

if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain> [--tor|--proxy]"
    echo "Examples:"
    echo "  $0 domain.com"
    echo "  $0 domain.com --tor"
    echo "  $0 domain.com --proxy"
    exit 1
fi

DOMAIN=$1
USE_ANONYMITY=$2
OUTPUT_DIR="anon_recon_$DOMAIN"
mkdir -p $OUTPUT_DIR
cd $OUTPUT_DIR

echo "[+] Starting anonymous reconnaissance for $DOMAIN"

# Setup anonymity if requested
if [ "$USE_ANONYMITY" = "--tor" ]; then
    echo "[+] Starting Tor service..."
    sudo systemctl start tor
    sleep 5
    export PROXY_CMD="proxychains4"
    echo "[+] Using Tor via ProxyChains"
elif [ "$USE_ANONYMITY" = "--proxy" ]; then
    export PROXY_CMD="proxychains4"
    echo "[+] Using ProxyChains configuration"
else
    export PROXY_CMD=""
fi

# Change MAC address for extra anonymity
echo "[+] Changing MAC address..."
sudo macchanger -r eth0 2>/dev/null || sudo macchanger -r wlan0 2>/dev/null || echo "[-] Could not change MAC"

# Subdomain enumeration with anonymity
echo "[+] Anonymous subdomain enumeration..."
$PROXY_CMD subfinder -d $DOMAIN -o subdomains_subfinder.txt
sleep 2
$PROXY_CMD assetfinder --subs-only $DOMAIN > subdomains_assetfinder.txt
sleep 2
cat subdomains_*.txt | sort -u > all_subdomains.txt

# Live subdomain check with delays
echo "[+] Checking live subdomains (with delays)..."
while read subdomain; do
    echo "Checking $subdomain"
    $PROXY_CMD httprobe <<< "$subdomain" >> live_subdomains.txt
    sleep $(shuf -i 1-3 -n 1)  # Random delay 1-3 seconds
done < all_subdomains.txt

# Port scanning with anonymity and delays
echo "[+] Anonymous port scanning..."
while read target; do
    echo "Scanning $target"
    $PROXY_CMD nmap -T2 -sS $target -oN "nmap_$target.txt"  # Slower, stealthier scan
    sleep $(shuf -i 5-10 -n 1)  # Random delay 5-10 seconds
done < live_subdomains.txt

# Directory bruteforcing with anonymity
echo "[+] Anonymous directory bruteforcing..."
while read subdomain; do
    echo "Directory scanning $subdomain"
    $PROXY_CMD gobuster dir -u "http://$subdomain" -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o "gobuster_$subdomain.txt" --delay 200ms
    sleep $(shuf -i 3-7 -n 1)  # Random delay
done < live_subdomains.txt

# OSINT with anonymity
echo "[+] Anonymous OSINT gathering..."
$PROXY_CMD python3 ~/tools/theHarvester/theHarvester.py -d $DOMAIN -b all -f theharvester_results.html

# Screenshot with anonymity
echo "[+] Taking anonymous screenshots..."
$PROXY_CMD gowitness file -f live_subdomains.txt --delay 3000

echo "[+] Anonymous reconnaissance complete. Check $OUTPUT_DIR for results."

# Clean up traces
echo "[+] Cleaning reconnaissance traces..."
history -c
unset HISTFILE
EOF
chmod +x ~/scripts/anon_recon.sh

# Create IP rotation and validation script
print_status "Creating IP rotation and validation script..."
cat > ~/scripts/ip_rotator.sh << 'EOF'
#!/bin/bash
# IP Rotation and Validation Script
# Rotates through different anonymity methods and validates IP changes

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

get_current_ip() {
    local method=$1
    case $method in
        "direct")
            curl -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "Failed"
            ;;
        "tor")
            curl -s --connect-timeout 10 --proxy socks5://127.0.0.1:9050 ifconfig.me 2>/dev/null || echo "Failed"
            ;;
        "proxychains")
            proxychains4 curl -s --connect-timeout 10 ifconfig.me 2>/dev/null | tail -1 || echo "Failed"
            ;;
    esac
}

check_tor_status() {
    if curl -s --proxy socks5://127.0.0.1:9050 https://check.torproject.org/api/ip | grep -q "true"; then
        return 0
    else
        return 1
    fi
}

rotate_tor_circuit() {
    print_status "Rotating Tor circuit..."
    echo -e 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT' | nc 127.0.0.1 9051
    sleep 10
}

change_mac_address() {
    print_status "Changing MAC address..."
    local interfaces=($(ip link show | grep -E '^[0-9]+:' | grep -v lo | cut -d: -f2 | tr -d ' '))
    
    for interface in "${interfaces[@]}"; do
        if [[ $interface != "lo" ]]; then
            sudo ifconfig $interface down 2>/dev/null
            sudo macchanger -r $interface 2>/dev/null
            sudo ifconfig $interface up 2>/dev/null
            print_status "MAC changed for $interface"
            break
        fi
    done
}

validate_anonymity() {
    print_status "Validating anonymity setup..."
    
    echo "Direct IP:"
    local direct_ip=$(get_current_ip "direct")
    echo "  $direct_ip"
    
    echo "Tor IP:"
    local tor_ip=$(get_current_ip "tor")
    echo "  $tor_ip"
    
    echo "ProxyChains IP:"
    local proxy_ip=$(get_current_ip "proxychains")
    echo "  $proxy_ip"
    
    # Check if IPs are different
    if [ "$direct_ip" != "$tor_ip" ] && [ "$tor_ip" != "Failed" ]; then
        print_status "Tor anonymity: WORKING ✓"
    else
        print_error "Tor anonymity: FAILED ✗"
    fi
    
    # DNS leak test
    print_status "Checking DNS leaks..."
    local dns_result=$(curl -s --proxy socks5://127.0.0.1:9050 "https://www.dnsleaktest.com/results.php?test_id=test" | grep -o "Your IP.*</span>" | head -1)
    if [[ $dns_result ]]; then
        echo "DNS test result: $dns_result"
    fi
}

start_rotation_cycle() {
    print_status "Starting IP rotation cycle..."
    local cycles=${1:-5}
    
    for i in $(seq 1 $cycles); do
        echo -e "\n${BLUE}=== Rotation Cycle $i ===${NC}"
        
        # Change MAC address
        change_mac_address
        
        # Rotate Tor circuit
        rotate_tor_circuit
        
        # Validate new IP
        local new_ip=$(get_current_ip "tor")
        print_status "New Tor IP: $new_ip"
        
        # Wait between cycles
        if [ $i -lt $cycles ]; then
            print_status "Waiting 30 seconds before next rotation..."
            sleep 30
        fi
    done
}

monitor_connections() {
    print_status "Monitoring network connections..."
    while true; do
        clear
        echo -e "${BLUE}=== Network Connection Monitor ===${NC}"
        echo "Current Tor IP: $(get_current_ip tor)"
        echo "Direct IP: $(get_current_ip direct)"
        echo ""
        echo "Active connections:"
        sudo netstat -tuln | grep -E ":(9050|9051|53)" | head -10
        echo ""
        echo "Press Ctrl+C to stop monitoring"
        sleep 5
    done
}

show_menu() {
    echo -e "${BLUE}===========================================${NC}"
    echo -e "${BLUE}         IP Rotation Manager${NC}"
    echo -e "${BLUE}===========================================${NC}"
    echo "1. Check current IPs"
    echo "2. Rotate Tor circuit"
    echo "3. Change MAC address"
    echo "4. Validate anonymity"
    echo "5. Start rotation cycle"
    echo "6. Monitor connections"
    echo "7. Exit"
    echo -e "${BLUE}===========================================${NC}"
}

# Main menu
if [ $# -eq 0 ]; then
    while true; do
        show_menu
        read -p "Select option [1-7]: " choice
        
        case $choice in
            1) 
                echo "Direct IP: $(get_current_ip direct)"
                echo "Tor IP: $(get_current_ip tor)"
                echo "ProxyChains IP: $(get_current_ip proxychains)"
                ;;
            2) rotate_tor_circuit ;;
            3) change_mac_address ;;
            4) validate_anonymity ;;
            5) 
                read -p "Number of rotation cycles [5]: " cycles
                cycles=${cycles:-5}
                start_rotation_cycle $cycles
                ;;
            6) monitor_connections ;;
            7) exit 0 ;;
            *) print_error "Invalid option" ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
else
    # Command line usage
    case $1 in
        "check") validate_anonymity ;;
        "rotate") rotate_tor_circuit ;;
        "mac") change_mac_address ;;
        "cycle") start_rotation_cycle ${2:-5} ;;
        *) echo "Usage: $0 [check|rotate|mac|cycle]" ;;
    esac
fi
EOF
chmod +x ~/scripts/ip_rotator.sh

# Create secure communication setup script
print_status "Creating secure communication setup script..."
cat > ~/scripts/secure_comms.sh << 'EOF'
#!/bin/bash
# Secure Communications Setup for Bug Bounty

print_status() {
    echo -e "\033[0;32m[+]\033[0m $1"
}

print_status "Setting up secure communications..."

# Install Signal Desktop
print_status "Installing Signal Desktop..."
wget -O- https://updates.signal.org/desktop/apt/keys.asc | gpg --dearmor > signal-desktop-keyring.gpg
sudo mv signal-desktop-keyring.gpg /usr/share/keyrings/
echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/signal-desktop-keyring.gpg] https://updates.signal.org/desktop/apt xenial main' | sudo tee /etc/apt/sources.list.d/signal-xenial.list
sudo apt update
sudo apt install -y signal-desktop

# Install Element (Matrix client)
print_status "Installing Element Matrix client..."
sudo wget -O /usr/share/keyrings/element-io-archive-keyring.gpg https://packages.element.io/debian/element-io-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/element-io-archive-keyring.gpg] https://packages.element.io/debian/ default main" | sudo tee /etc/apt/sources.list.d/element-io.list
sudo apt update
sudo apt install -y element-desktop

# Install ProtonMail Bridge (if available)
print_status "Installing ProtonMail Bridge dependencies..."
sudo apt install -y pass gnupg2

# Setup GPG for secure communications
print_status "Setting up GPG..."
if [ ! -f ~/.gnupg/gpg.conf ]; then
    mkdir -p ~/.gnupg
    chmod 700 ~/.gnupg
    cat > ~/.gnupg/gpg.conf << 'GPGEOF'
# GPG configuration for enhanced security
default-key-algo RSA4096
cert-digest-algo SHA512
cipher-algo AES256
digest-algo SHA512
compress-algo 2
s2k-digest-algo SHA512
s2k-cipher-algo AES256
s2k-count 65536
no-emit-version
no-comments
armor
GPGEOF
fi

print_status "Secure communications setup complete!"
print_status "Installed: Signal Desktop, Element Matrix, GPG configured"
EOF
chmod +x ~/scripts/secure_comms.sh

# Create VM snapshot automation script
print_status "Creating VM snapshot automation script..."
cat > ~/scripts/vm_snapshots.sh << 'EOF'
#!/bin/bash
# VirtualBox Snapshot Automation for Anonymity

print_status() {
    echo -e "\033[0;32m[+]\033[0m $1"
}

print_warning() {
    echo -e "\033[1;33m[!]\033[0m $1"
}

# Note: This script provides guidance for VirtualBox snapshot management
# VBoxManage commands need to be run from the host system

cat << 'VMEOF'
=== VirtualBox Snapshot Management Guide ===

For maximum anonymity and security, use these VBoxManage commands on your HOST system:

1. Create a clean baseline snapshot:
   VBoxManage snapshot "KaliVM" take "CleanBaseline" --description "Fresh Kali install with tools"

2. Create operation-specific snapshots:
   VBoxManage snapshot "KaliVM" take "PreRecon" --description "Before reconnaissance"
   VBoxManage snapshot "KaliVM" take "PreExploit" --description "Before exploitation"

3. Restore to clean state:
   VBoxManage snapshot "KaliVM" restore "CleanBaseline"

4. List all snapshots:
   VBoxManage snapshot "KaliVM" list

5. Delete old snapshots:
   VBoxManage snapshot "KaliVM" delete "SnapshotName"

AUTOMATION WORKFLOW:
- Take snapshot before each target
- Restore to clean snapshot after operations
- Never save credentials or sensitive data permanently
- Use separate snapshots for different clients/targets

VM SECURITY CHECKLIST:
□ Guest Additions NOT installed
□ Network set to NAT (not Bridged)
□ MAC address randomized
□ Host-only adapters disabled
□ Shared folders disabled
□ Clipboard sharing disabled
□ 3D acceleration disabled
□ USB controller disabled (if not needed)
VMEOF

# Create snapshot reminder service
cat > ~/.config/systemd/user/snapshot-reminder.service << 'SYSTEMDEOF'
[Unit]
Description=VM Snapshot Reminder
Wants=snapshot-reminder.timer

[Service]
Type=oneshot
ExecStart=/usr/bin/notify-send "VM Security" "Remember to revert to clean snapshot after operations!"

[Install]
WantedBy=multi-user.target
SYSTEMDEOF

cat > ~/.config/systemd/user/snapshot-reminder.timer << 'TIMEREOF'
[Unit]
Description=Run snapshot reminder every 2 hours
Requires=snapshot-reminder.service

[Timer]
OnCalendar=*:0/120
Persistent=true

[Install]
WantedBy=timers.target
TIMEREOF

print_status "VM snapshot management guide created!"
print_warning "Run 'systemctl --user enable snapshot-reminder.timer' to enable reminders"
EOF
chmod +x ~/scripts/vm_snapshots.sh

# Create traffic analysis detection script
print_status "Creating traffic analysis detection script..."
cat > ~/scripts/traffic_analysis.py << 'EOF'
#!/usr/bin/env python3
"""
Traffic Analysis and Detection Evasion Script
Monitors network traffic patterns and suggests evasion techniques
"""

import psutil
import time
import random
import subprocess
import threading
from collections import defaultdict, deque

class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.traffic_history = deque(maxlen=100)
        self.suspicious_patterns = []
        
    def monitor_connections(self, duration=60):
        """Monitor network connections for suspicious patterns"""
        print(f"[+] Monitoring network traffic for {duration} seconds...")
        
        start_time = time.time()
        while time.time() - start_time < duration:
            connections = psutil.net_connections(kind='inet')
            
            current_connections = []
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    current_connections.append({
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "None",
                        'pid': conn.pid
                    })
            
            self.traffic_history.append({
                'timestamp': time.time(),
                'connections': current_connections,
                'count': len(current_connections)
            })
            
            time.sleep(1)
        
        self.analyze_patterns()
    
    def analyze_patterns(self):
        """Analyze traffic patterns for potential detection risks"""
        print("\n[+] Analyzing traffic patterns...")
        
        # Check for consistent timing patterns
        connection_counts = [entry['count'] for entry in self.traffic_history]
        if len(set(connection_counts)) < 3:
            self.suspicious_patterns.append("Consistent connection count pattern detected")
        
        # Check for regular intervals
        timestamps = [entry['timestamp'] for entry in self.traffic_history]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        
        if all(abs(interval - avg_interval) < 0.1 for interval in intervals):
            self.suspicious_patterns.append("Regular timing pattern detected")
        
        # Check for single destination dominance
        destinations = defaultdict(int)
        for entry in self.traffic_history:
            for conn in entry['connections']:
                if conn['remote'] != "None":
                    dest_ip = conn['remote'].split(':')[0]
                    destinations[dest_ip] += 1
        
        if destinations:
            most_common = max(destinations.values())
            total_connections = sum(destinations.values())
            if most_common / total_connections > 0.8:
                self.suspicious_patterns.append("Traffic concentrated to single destination")
        
        self.print_analysis()
    
    def print_analysis(self):
        """Print traffic analysis results"""
        print("\n" + "="*50)
        print("TRAFFIC ANALYSIS REPORT")
        print("="*50)
        
        if self.suspicious_patterns:
            print("⚠️  SUSPICIOUS PATTERNS DETECTED:")
            for pattern in self.suspicious_patterns:
                print(f"   - {pattern}")
            print("\n🛡️  RECOMMENDED COUNTERMEASURES:")
            print("   - Add random delays between requests")
            print("   - Vary request timing patterns")
            print("   - Use multiple exit nodes/proxies")
            print("   - Implement traffic padding")
        else:
            print("✅ No obvious suspicious patterns detected")
        
        print(f"\n📊 STATISTICS:")
        print(f"   - Total monitoring time: {len(self.traffic_history)} seconds")
        print(f"   - Average connections: {sum(entry['count'] for entry in self.traffic_history) / len(self.traffic_history):.1f}")
        
        # Show top destinations
        destinations = defaultdict(int)
        for entry in self.traffic_history:
            for conn in entry['connections']:
                if conn['remote'] != "None":
                    dest_ip = conn['remote'].split(':')[0]
                    destinations[dest_ip] += 1
        
        if destinations:
            print(f"   - Top destinations:")
            for dest, count in sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"     {dest}: {count} connections")
    
    def generate_cover_traffic(self, duration=300):
        """Generate cover traffic to obfuscate real activity"""
        print(f"[+] Generating cover traffic for {duration} seconds...")
        
        sites = [
            'https://www.google.com',
            'https://www.wikipedia.org',
            'https://www.github.com',
            'https://www.stackoverflow.com',
            'https://www.reddit.com'
        ]
        
        def make_request():
            site = random.choice(sites)
            try:
                subprocess.run(['curl', '-s', '--connect-timeout', '5', site], 
                             capture_output=True, timeout=10)
            except:
                pass
        
        start_time = time.time()
        while time.time() - start_time < duration:
            # Random delay between 5-30 seconds
            delay = random.uniform(5, 30)
            time.sleep(delay)
            
            # Make 1-3 random requests
            for _ in range(random.randint(1, 3)):
                threading.Thread(target=make_request).start()
                time.sleep(random.uniform(0.5, 2))

def main():
    analyzer = TrafficAnalyzer()
    
    print("Traffic Analysis and Evasion Tool")
    print("1. Monitor current traffic")
    print("2. Generate cover traffic")
    print("3. Monitor + Cover traffic")
    
    choice = input("Select option [1-3]: ")
    
    if choice == '1':
        duration = int(input("Monitor duration (seconds) [60]: ") or 60)
        analyzer.monitor_connections(duration)
    elif choice == '2':
        duration = int(input("Cover traffic duration (seconds) [300]: ") or 300)
        analyzer.generate_cover_traffic(duration)
    elif choice == '3':
        monitor_duration = int(input("Monitor duration (seconds) [60]: ") or 60)
        cover_duration = int(input("Cover traffic duration (seconds) [300]: ") or 300)
        
        # Start cover traffic in background
        cover_thread = threading.Thread(target=analyzer.generate_cover_traffic, args=(cover_duration,))
        cover_thread.start()
        
        # Monitor traffic
        analyzer.monitor_connections(monitor_duration)
        
        cover_thread.join()

if __name__ == "__main__":
    main()
EOF
chmod +x ~/scripts/traffic_analysis.py

# Kali Linux Bug Bounty Complete Setup Script
# Author: Security Researcher Setup
# Description: Comprehensive setup for bug bounty hunting on fresh Kali Linux

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   exit 1
fi

print_info "Starting Kali Linux Bug Bounty Setup..."

# Update system
print_status "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install essential packages
print_status "Installing essential packages..."
sudo apt install -y curl wget git vim nano htop tree unzip zip rar p7zip-full \
    build-essential software-properties-common apt-transport-https ca-certificates \
    gnupg lsb-release python3-pip python3-venv nodejs npm golang-go ruby-full \
    openjdk-11-jdk maven gradle php composer perl cpanminus rustc cargo \
    docker.io docker-compose postgresql redis-server mongodb

# Install ZSH and Oh My Zsh
print_status "Installing ZSH and Oh My Zsh..."
sudo apt install -y zsh fonts-powerline
sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

# Install ZSH plugins
print_status "Installing ZSH plugins..."
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
git clone https://github.com/zsh-users/zsh-completions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-completions

# Configure ZSH
print_status "Configuring ZSH..."
cp ~/.zshrc ~/.zshrc.backup
cat > ~/.zshrc << 'EOF'
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="agnoster"
plugins=(
    git
    docker
    docker-compose
    golang
    python
    node
    npm
    ruby
    zsh-autosuggestions
    zsh-syntax-highlighting
    zsh-completions
)
source $ZSH/oh-my-zsh.sh

# Custom aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'
alias h='history'
alias j='jobs -l'
alias ports='netstat -tulanp'
alias myip='curl ifconfig.me'

# Bug bounty aliases
alias nmap-quick='nmap -T4 -F'
alias nmap-full='nmap -T4 -A -v'
alias dirb-common='dirb $1 /usr/share/wordlists/dirb/common.txt'
alias gobuster-dir='gobuster dir -u $1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
alias sqlmap-basic='sqlmap -u $1 --batch --banner'
alias nikto-scan='nikto -h $1'

# Programming environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
export PATH=$PATH:$HOME/.local/bin
export PATH=$PATH:$HOME/bin
export EDITOR=nano
EOF

# Set ZSH as default shell
sudo chsh -s $(which zsh) $USER

# Create directory structure
print_status "Creating directory structure..."
mkdir -p ~/tools
mkdir -p ~/wordlists
mkdir -p ~/scripts
mkdir -p ~/go/bin
mkdir -p ~/.local/bin

# Install Python tools
print_status "Installing Python bug bounty tools..."
pip3 install --user requests beautifulsoup4 lxml scrapy selenium pyfiglet colorama \
    dnspython python-nmap scapy impacket pycrypto cryptography jwt hashcat-utils \
    dirsearch subfinder httpx nuclei-templates sublister sublist3r knockpy \
    dnsrecon theHarvester shodan censys-python recon-ng wafw00f sqlmap \
    paramspider arjun secretfinder linkfinder js-beautify wapiti3 \
    xsstrike corscanner race-the-web s3scanner cloudsplaining

# Install Node.js tools
print_status "Installing Node.js bug bounty tools..."
npm install -g @projectdiscovery/nuclei @projectdiscovery/httpx @projectdiscovery/subfinder \
    @projectdiscovery/naabu @projectdiscovery/dnsx retire js-beautify \
    wappalyzer-cli gau waybackurls meg linkfinder subjs getJS \
    observatory-cli ssllabs-scan testssl.sh-cli

# Install Go tools
print_status "Installing Go bug bounty tools..."
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/notify/cmd/notify@latest
go install github.com/projectdiscovery/proxify/cmd/proxify@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/fff@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/meg@latest
go install github.com/lc/gau@latest
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest
go install github.com/sensepost/gowitness@latest
go install github.com/Emoe/kxss@latest
go install github.com/michenriksen/aquatone@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/hakluke/hakrevdns@latest
go install github.com/hakluke/haklistgen@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest

# Install Ruby tools
print_status "Installing Ruby bug bounty tools..."
gem install wpscan
gem install sslyze
gem install brakeman

# Clone GitHub repositories
print_status "Cloning essential GitHub repositories..."
cd ~/tools

# Subdomain enumeration
git clone https://github.com/aboul3la/Sublist3r.git
git clone https://github.com/TheRook/subbrute.git
git clone https://github.com/nsonaniya2010/SubDomainizer.git
git clone https://github.com/Ice3man543/SubOver.git
git clone https://github.com/UnaPibaGeek/ctfr.git
git clone https://github.com/blechschmidt/massdns.git
git clone https://github.com/projectdiscovery/chaos-client.git

# Web application testing
git clone https://github.com/maurosoria/dirsearch.git
git clone https://github.com/xmendez/wfuzz.git
git clone https://github.com/s0md3v/XSStrike.git
git clone https://github.com/s0md3v/Photon.git
git clone https://github.com/s0md3v/Arjun.git
git clone https://github.com/s0md3v/Corsy.git
git clone https://github.com/s0md3v/Bolt.git
git clone https://github.com/GerbenJavado/LinkFinder.git
git clone https://github.com/devanshbatham/ParamSpider.git
git clone https://github.com/m4ll0k/SecretFinder.git
git clone https://github.com/EnableSecurity/wafw00f.git
git clone https://github.com/sandrogauci/sipsak.git

# Exploitation frameworks
git clone https://github.com/sqlmapproject/sqlmap.git
git clone https://github.com/commixproject/commix.git
git clone https://github.com/SwisskyPayloads/PayloadsAllTheThings.git
git clone https://github.com/danielmiessler/SecLists.git ~/wordlists/SecLists
git clone https://github.com/fuzzdb-project/fuzzdb.git ~/wordlists/fuzzdb

# OSINT tools
git clone https://github.com/laramies/theHarvester.git
git clone https://github.com/sherlock-project/sherlock.git
git clone https://github.com/smicallef/spiderfoot.git
git clone https://github.com/bhavsec/reconspider.git
git clone https://github.com/opsdisk/metagoofil.git

# Network tools
git clone https://github.com/robertdavidgraham/masscan.git
git clone https://github.com/zmap/zmap.git
git clone https://github.com/RustScan/RustScan.git

# Cloud security
git clone https://github.com/nccgroup/ScoutSuite.git
git clone https://github.com/sa7mon/S3Scanner.git
git clone https://github.com/jordanpotti/CloudScraper.git
git clone https://github.com/VirtueSecurity/aws-extender.git

# Mobile security
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
git clone https://github.com/sensepost/objection.git

# Anonymity and VPN tools
git clone https://github.com/Und3rf10w/kali-anonsurf.git
git clone https://github.com/brainfucksec/kalitorify.git
git clone https://github.com/epidemics-scepticism/writing-simple-proxy-rotator.git
git clone https://github.com/SusmithKrishnan/torghost.git
git clone https://github.com/ultrafunkamsterdam/undetected-chromedriver.git
git clone https://github.com/MasterScrat/Chaturbate-Anonymous.git ~/tools/proxy-tools
git clone https://github.com/rootSySdk/AnonSurf.git

# Additional security tools
git clone https://github.com/pentestmonkey/unix-privesc-check.git
git clone https://github.com/rebootuser/LinEnum.git
git clone https://github.com/carlospolop/PEASS-ng.git
git clone https://github.com/Diego-Trevor/CVE-2021-44228-PoC.git
git clone https://github.com/projectdiscovery/nuclei-templates.git

# Configure anonymity tools
print_status "Configuring anonymity and VPN tools..."

# Install and configure AnonSurf
cd ~/tools/kali-anonsurf
sudo ./installer.sh

# Install kalitorify
cd ~/tools/kalitorify
sudo make install

# Configure Tor
print_status "Configuring Tor..."
sudo systemctl stop tor
sudo cp /etc/tor/torrc /etc/tor/torrc.backup
sudo cat > /etc/tor/torrc << 'EOF'
# Tor configuration for enhanced anonymity
SocksPort 9050
SocksPolicy accept 127.0.0.1/8
SocksPolicy accept 192.168.0.0/16
SocksPolicy accept 10.0.0.0/8
SocksPolicy reject *

# Control port
ControlPort 9051
HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C

# DNS
DNSPort 53
AutomapHostsOnResolve 1
AutomapHostsSuffixes .onion,.exit

# Hidden services
HiddenServiceStatistics 0

# Exit policies
ExitPolicy reject *:*

# Entry guards
UseEntryGuards 1
NumEntryGuards 3

# Circuits
MaxCircuitDirtiness 600
NewCircuitPeriod 30
MaxOnionsPending 100

# Security settings
DisableDebuggerAttachment 0
SafeLogging 1
EOF

# Configure ProxyChains
print_status "Configuring ProxyChains..."
sudo cp /etc/proxychains4.conf /etc/proxychains4.conf.backup
sudo cat > /etc/proxychains4.conf << 'EOF'
# ProxyChains configuration
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
localnet 127.0.0.0/255.0.0.0
localnet 10.0.0.0/255.0.0.0
localnet 172.16.0.0/255.240.0.0
localnet 192.168.0.0/255.255.0.0

[ProxyList]
# Tor
socks5 127.0.0.1 9050
# Add your additional SOCKS5 proxies here
# socks5 proxy-server.com 1080
# http proxy-server.com 8080
EOF

# Configure MAC address randomization
print_status "Setting up MAC address randomization..."
sudo cat > /etc/systemd/system/macchanger.service << 'EOF'
[Unit]
Description=MAC Address Changer
Wants=network-pre.target
Before=network-pre.target
BindsTo=sys-subsystem-net-devices-%i.device
After=sys-subsystem-net-devices-%i.device

[Service]
ExecStart=/usr/bin/macchanger -r %I
Type=oneshot
TimeoutStartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable MAC randomization for common interfaces
sudo systemctl enable macchanger@eth0.service
sudo systemctl enable macchanger@wlan0.service

# Configure UFW firewall
print_status "Configuring UFW firewall..."
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default deny outgoing
sudo ufw allow out 53
sudo ufw allow out 80
sudo ufw allow out 443
sudo ufw allow out 9050
sudo ufw allow out 9051
sudo ufw allow out on tun0
sudo ufw enable

# Create VirtualBox specific configurations
print_status "Creating VirtualBox specific configurations..."
cat > ~/scripts/vbox_anon_setup.sh << 'EOF'
#!/bin/bash
# VirtualBox Anonymity Setup Script

print_status() {
    echo -e "\033[0;32m[+]\033[0m $1"
}

print_warning() {
    echo -e "\033[1;33m[!]\033[0m $1"
}

print_status "Setting up VirtualBox for maximum anonymity..."

# Disable VirtualBox Guest Additions if installed
print_warning "Make sure VirtualBox Guest Additions are NOT installed"
print_warning "Guest Additions can leak host information"

# Configure network settings
print_status "Network configuration recommendations:"
echo "1. Use NAT or NAT Network (never Bridged)"
echo "2. Enable 'Cable Connected' option"
echo "3. Set Adapter Type to 'Intel PRO/1000 MT Desktop'"
echo "4. Generate new MAC address regularly"

# Set up hostname randomization
print_status "Setting up hostname randomization..."
RANDOM_HOSTNAME="kali-$(openssl rand -hex 4)"
sudo hostnamectl set-hostname $RANDOM_HOSTNAME
echo "127.0.0.1 $RANDOM_HOSTNAME" | sudo tee -a /etc/hosts

# Timezone randomization
print_status "Randomizing timezone..."
TIMEZONES=("America/New_York" "Europe/London" "Asia/Tokyo" "Australia/Sydney" "America/Los_Angeles" "Europe/Berlin")
RANDOM_TZ=${TIMEZONES[$RANDOM % ${#TIMEZONES[@]}]}
sudo timedatectl set-timezone $RANDOM_TZ
print_status "Timezone set to: $RANDOM_TZ"

# Clear system logs
print_status "Clearing system logs..."
sudo journalctl --vacuum-time=1s
sudo rm -rf /var/log/*
sudo rm -rf /tmp/*
sudo rm -rf ~/.bash_history
sudo rm -rf ~/.zsh_history

print_status "VirtualBox anonymity setup complete!"
print_warning "Remember to:"
print_warning "1. Take snapshots before sensitive operations"
print_warning "2. Revert to clean snapshots regularly"
print_warning "3. Never save credentials on the VM"
print_warning "4. Use disposable VMs for high-risk activities"
EOF
chmod +x ~/scripts/vbox_anon_setup.sh

# Install massdns
cd ~/tools/massdns
make
sudo make install

# Install RustScan
cd ~/tools/RustScan
cargo build --release
sudo cp target/release/rustscan /usr/local/bin/

# Install additional Kali tools
print_status "Installing additional Kali tools..."
sudo apt install -y nmap masscan gobuster dirb nikto wpscan sqlmap burpsuite \
    zaproxy metasploit-framework armitage beef-xss wireshark tcpdump \
    john hashcat hydra medusa patator aircrack-ng reaver wifite \
    binwalk foremost volatility yara gdb radare2 ghidra ida-free \
    searchsploit exploitdb set social-engineer-toolkit king-phisher \
    maltego spiderfoot theharvester shodan recon-ng dmitry fierce \
    dnsrecon dnswalk sublist3r knockpy amass subfinder assetfinder

# Install browser tools
print_status "Installing browser extensions and tools..."
wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt update
sudo apt install -y google-chrome-stable firefox-esr

# Install and configure Nuclei templates
print_status "Setting up Nuclei templates..."
nuclei -update-templates

# Install Burp Suite extensions setup script
print_status "Creating Burp Suite extensions setup script..."
cat > ~/scripts/burp_extensions.sh << 'EOF'
#!/bin/bash
# Burp Suite Extension URLs
echo "Download these extensions manually from Burp Suite Pro/Community:"
echo "1. Autorize - Authorization testing"
echo "2. Param Miner - Parameter discovery"
echo "3. Backslash Powered Scanner - Advanced scanning"
echo "4. Upload Scanner - File upload testing"
echo "5. Content Type Converter - Content manipulation"
echo "6. J2EEScan - J2EE vulnerability scanner"
echo "7. Active Scan++ - Extended active scanning"
echo "8. Hackvertor - Encoding/decoding"
echo "9. Collaborator Everywhere - Burp Collaborator integration"
echo "10. Software Vulnerability Scanner - CVE detection"
EOF
chmod +x ~/scripts/burp_extensions.sh

# Create reconnaissance automation script
print_status "Creating reconnaissance automation script..."
cat > ~/scripts/recon.sh << 'EOF'
#!/bin/bash
# Automated reconnaissance script
# Usage: ./recon.sh domain.com

if [ $# -eq 0 ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR="recon_$DOMAIN"
mkdir -p $OUTPUT_DIR
cd $OUTPUT_DIR

echo "[+] Starting reconnaissance for $DOMAIN"

# Subdomain enumeration
echo "[+] Subdomain enumeration..."
subfinder -d $DOMAIN -o subdomains_subfinder.txt
assetfinder --subs-only $DOMAIN > subdomains_assetfinder.txt
amass enum -d $DOMAIN -o subdomains_amass.txt
cat subdomains_*.txt | sort -u > all_subdomains.txt

# Live subdomain check
echo "[+] Checking live subdomains..."
cat all_subdomains.txt | httprobe > live_subdomains.txt

# Port scanning
echo "[+] Port scanning..."
nmap -iL live_subdomains.txt -T4 -oN nmap_scan.txt

# Directory bruteforcing
echo "[+] Directory bruteforcing..."
while read subdomain; do
    echo "Scanning $subdomain"
    gobuster dir -u "http://$subdomain" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o "gobuster_$subdomain.txt"
done < live_subdomains.txt

# Screenshot
echo "[+] Taking screenshots..."
gowitness file -f live_subdomains.txt

echo "[+] Reconnaissance complete. Check $OUTPUT_DIR for results."
EOF
chmod +x ~/scripts/recon.sh

# Create XSS testing script
print_status "Creating XSS testing script..."
cat > ~/scripts/xss_test.sh << 'EOF'
#!/bin/bash
# XSS testing automation script
# Usage: ./xss_test.sh <url>

if [ $# -eq 0 ]; then
    echo "Usage: $0 <url>"
    exit 1
fi

URL=$1
echo "[+] Testing XSS on $URL"

# Using XSStrike
python3 ~/tools/XSStrike/xsstrike.py -u "$URL"

# Using dalfox
dalfox url "$URL"

# Using kxss
echo "$URL" | kxss

echo "[+] XSS testing complete"
EOF
chmod +x ~/scripts/xss_test.sh

# Create VPN management script
print_status "Creating VPN management script..."
cat > ~/scripts/vpn_manager.sh << 'EOF'
#!/bin/bash
# VPN and Anonymity Manager Script

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

show_menu() {
    echo -e "${BLUE}===========================================${NC}"
    echo -e "${BLUE}      VPN & Anonymity Manager${NC}"
    echo -e "${BLUE}===========================================${NC}"
    echo "1. Start Tor (Anonymous browsing)"
    echo "2. Stop Tor"
    echo "3. Start AnonSurf (System-wide anonymity)"
    echo "4. Stop AnonSurf"
    echo "5. Connect ProtonVPN"
    echo "6. Disconnect ProtonVPN"
    echo "7. Check IP and location"
    echo "8. Change MAC address"
    echo "9. Start Kalitorify"
    echo "10. Stop Kalitorify"
    echo "11. Configure ProxyChains"
    echo "12. Test anonymity"
    echo "13. Clear tracks"
    echo "14. Exit"
    echo -e "${BLUE}===========================================${NC}"
}

check_ip() {
    print_status "Checking current IP and location..."
    echo "Regular IP check:"
    curl -s ifconfig.me
    echo ""
    echo "Tor check:"
    curl -s --proxy socks5://127.0.0.1:9050 https://check.torproject.org/api/ip
    echo ""
    echo "Location info:"
    curl -s ipinfo.io
}

start_tor() {
    print_status "Starting Tor service..."
    sudo systemctl start tor
    sleep 3
    if systemctl is-active --quiet tor; then
        print_status "Tor is running. SOCKS proxy available at 127.0.0.1:9050"
        print_warning "Configure your browser to use SOCKS5 proxy 127.0.0.1:9050"
    else
        print_error "Failed to start Tor"
    fi
}

stop_tor() {
    print_status "Stopping Tor service..."
    sudo systemctl stop tor
    print_status "Tor stopped"
}

start_anonsurf() {
    print_status "Starting AnonSurf (system-wide anonymity)..."
    if command -v anonsurf &> /dev/null; then
        sudo anonsurf start
    else
        print_error "AnonSurf not installed. Install from ~/tools/kali-anonsurf"
    fi
}

stop_anonsurf() {
    print_status "Stopping AnonSurf..."
    if command -v anonsurf &> /dev/null; then
        sudo anonsurf stop
    else
        print_error "AnonSurf not installed"
    fi
}

connect_protonvpn() {
    print_status "Connecting to ProtonVPN..."
    if command -v protonvpn-cli &> /dev/null; then
        echo "Available servers:"
        protonvpn-cli list
        read -p "Enter server name (or 'fastest' for automatic): " server
        if [ "$server" = "fastest" ]; then
            protonvpn-cli connect --fastest
        else
            protonvpn-cli connect $server
        fi
    else
        print_error "ProtonVPN CLI not installed"
    fi
}

disconnect_protonvpn() {
    print_status "Disconnecting ProtonVPN..."
    if command -v protonvpn-cli &> /dev/null; then
        protonvpn-cli disconnect
    else
        print_error "ProtonVPN CLI not installed"
    fi
}

change_mac() {
    print_status "Changing MAC address..."
    interfaces=$(ip link show | grep -E '^[0-9]+:' | grep -v lo | cut -d: -f2 | tr -d ' ')
    echo "Available interfaces:"
    echo "$interfaces"
    read -p "Enter interface name: " interface
    if [[ $interfaces == *"$interface"* ]]; then
        sudo ifconfig $interface down
        sudo macchanger -r $interface
        sudo ifconfig $interface up
        print_status "MAC address changed for $interface"
    else
        print_error "Invalid interface"
    fi
}

start_kalitorify() {
    print_status "Starting Kalitorify..."
    if command -v kalitorify &> /dev/null; then
        sudo kalitorify --tor
    else
        print_error "Kalitorify not installed. Install from ~/tools/kalitorify"
    fi
}

stop_kalitorify() {
    print_status "Stopping Kalitorify..."
    if command -v kalitorify &> /dev/null; then
        sudo kalitorify --clearnet
    else
        print_error "Kalitorify not installed"
    fi
}

configure_proxychains() {
    print_status "Configuring ProxyChains..."
    echo "Current ProxyChains configuration:"
    cat /etc/proxychains4.conf | grep -A 20 "\[ProxyList\]"
    echo ""
    read -p "Add new proxy? (y/n): " add_proxy
    if [ "$add_proxy" = "y" ]; then
        read -p "Proxy type (socks4/socks5/http): " proxy_type
        read -p "Proxy host: " proxy_host
        read -p "Proxy port: " proxy_port
        echo "$proxy_type $proxy_host $proxy_port" | sudo tee -a /etc/proxychains4.conf
        print_status "Proxy added to ProxyChains"
    fi
}

test_anonymity() {
    print_status "Testing anonymity setup..."
    echo "=== Regular Connection ==="
    curl -s ifconfig.me
    echo ""
    echo ""
    echo "=== Through Tor ==="
    curl -s --proxy socks5://127.0.0.1:9050 https://check.torproject.org/api/ip
    echo ""
    echo ""
    echo "=== Through ProxyChains ==="
    proxychains4 curl -s ifconfig.me
    echo ""
    echo ""
    echo "=== DNS Leak Test ==="
    curl -s https://www.dnsleaktest.com/
}

clear_tracks() {
    print_status "Clearing tracks and logs..."
    
    # Clear bash history
    history -c
    history -w
    rm -f ~/.bash_history
    rm -f ~/.zsh_history
    
    # Clear system logs
    sudo journalctl --vacuum-time=1s
    
    # Clear temporary files
    sudo rm -rf /tmp/*
    sudo rm -rf /var/tmp/*
    
    # Clear browser cache (if exists)
    rm -rf ~/.cache/google-chrome/
    rm -rf ~/.cache/firefox/
    rm -rf ~/.mozilla/firefox/*/Cache/
    
    # Clear recent files
    rm -f ~/.recently-used
    rm -f ~/.local/share/recently-used.xbel
    
    # Secure delete swap
    sudo swapoff -a
    sudo swapon -a
    
    print_status "Tracks cleared!"
}

# Main menu loop
while true; do
    show_menu
    read -p "Select option [1-14]: " choice
    
    case $choice in
        1) start_tor ;;
        2) stop_tor ;;
        3) start_anonsurf ;;
        4) stop_anonsurf ;;
        5) connect_protonvpn ;;
        6) disconnect_protonvpn ;;
        7) check_ip ;;
        8) change_mac ;;
        9) start_kalitorify ;;
        10) stop_kalitorify ;;
        11) configure_proxychains ;;
        12) test_anonymity ;;
        13) clear_tracks ;;
        14) exit 0 ;;
        *) print_error "Invalid option" ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
    clear
done
EOF
chmod +x ~/scripts/vpn_manager.sh

# Create proxy rotation script
print_status "Creating proxy rotation script..."
cat > ~/scripts/proxy_rotator.py << 'EOF'
#!/usr/bin/env python3
"""
Proxy Rotator for Anonymous Web Requests
Usage: python3 proxy_rotator.py <url>
"""

import requests
import random
import time
import sys
from fake_useragent import UserAgent
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ProxyRotator:
    def __init__(self):
        self.ua = UserAgent()
        self.proxies = [
            # Add your proxy list here
            # Format: {'http': 'http://proxy:port', 'https': 'http://proxy:port'}
            {'http': 'socks5://127.0.0.1:9050', 'https': 'socks5://127.0.0.1:9050'},  # Tor
        ]
        self.session = requests.Session()
    
    def get_random_headers(self):
        return {
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
    
    def make_request(self, url, max_retries=3):
        for attempt in range(max_retries):
            try:
                proxy = random.choice(self.proxies)
                headers = self.get_random_headers()
                
                print(f"[+] Attempt {attempt + 1}: Using proxy {proxy}")
                
                response = self.session.get(
                    url,
                    proxies=proxy,
                    headers=headers,
                    timeout=10,
                    verify=False
                )
                
                if response.status_code == 200:
                    print(f"[+] Success! Status: {response.status_code}")
                    return response
                
            except Exception as e:
                print(f"[-] Attempt {attempt + 1} failed: {str(e)}")
                time.sleep(2)
        
        print("[-] All attempts failed")
        return None
    
    def check_ip(self):
        """Check current IP address"""
        try:
            response = self.make_request('http://httpbin.org/ip')
            if response:
                print(f"[+] Current IP: {response.json()}")
        except Exception as e:
            print(f"[-] Error checking IP: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 proxy_rotator.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    rotator = ProxyRotator()
    
    print("[+] Checking IP before request...")
    rotator.check_ip()
    
    print(f"[+] Making request to: {url}")
    response = rotator.make_request(url)
    
    if response:
        print(f"[+] Response length: {len(response.text)} characters")
        print(f"[+] Response headers: {dict(response.headers)}")
EOF
chmod +x ~/scripts/proxy_rotator.py

# Create Tor browser automation script
print_status "Creating Tor browser automation script..."
cat > ~/scripts/tor_browser_automation.py << 'EOF'
#!/usr/bin/env python3
"""
Tor Browser Automation for Anonymous Web Testing
"""

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.common.proxy import Proxy, ProxyType
import time
import random

class TorBrowser:
    def __init__(self):
        self.driver = None
        self.setup_driver()
    
    def setup_driver(self):
        """Setup Tor Browser with Selenium"""
        options = Options()
        options.add_argument('--headless')  # Remove for GUI
        
        # Tor proxy settings
        proxy = Proxy()
        proxy.proxy_type = ProxyType.MANUAL
        proxy.socks_proxy = "127.0.0.1:9050"
        proxy.socks_version = 5
        
        # Firefox profile for Tor
        profile = webdriver.FirefoxProfile()
        profile.set_preference("network.proxy.type", 1)
        profile.set_preference("network.proxy.socks", "127.0.0.1")
        profile.set_preference("network.proxy.socks_port", 9050)
        profile.set_preference("network.proxy.socks_version", 5)
        profile.set_preference("network.proxy.socks_remote_dns", True)
        
        # Privacy settings
        profile.set_preference("privacy.trackingprotection.enabled", True)
        profile.set_preference("geo.enabled", False)
        profile.set_preference("media.navigator.enabled", False)
        profile.set_preference("webgl.disabled", True)
        
        self.driver = webdriver.Firefox(options=options, firefox_profile=profile)
        self.driver.set_page_load_timeout(30)
    
    def visit_url(self, url):
        """Visit URL anonymously"""
        try:
            print(f"[+] Visiting: {url}")
            self.driver.get(url)
            time.sleep(random.uniform(2, 5))  # Random delay
            return True
        except Exception as e:
            print(f"[-] Error visiting {url}: {str(e)}")
            return False
    
    def check_ip(self):
        """Check current IP through Tor"""
        if self.visit_url("https://check.torproject.org/"):
            page_source = self.driver.page_source
            if "Congratulations" in page_source:
                print("[+] Successfully connected through Tor!")
            else:
                print("[-] Not connected through Tor!")
    
    def close(self):
        """Close browser"""
        if self.driver:
            self.driver.quit()

if __name__ == "__main__":
    browser = TorBrowser()
    browser.check_ip()
    browser.close()
EOF
chmod +x ~/scripts/tor_browser_automation.py

# Install specific tools that need compilation
print_status "Installing and compiling specific tools..."

# Install Docker containers for testing
print_status "Setting up Docker containers for testing..."
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER

# Pull useful Docker images
sudo docker pull owasp/zap2docker-stable
sudo docker pull owasp/webgoat8
sudo docker pull vulnerables/web-dvwa
sudo docker pull citizenstig/dvwa
sudo docker pull webpwnized/mutillidae

# Configure Git
print_status "Configuring Git..."
read -p "Enter your Git username: " git_username
read -p "Enter your Git email: " git_email
git config --global user.name "$git_username"
git config --global user.email "$git_email"

# Create useful aliases file
print_status "Creating aliases file..."
cat > ~/scripts/aliases.sh << 'EOF'
#!/bin/bash
# Useful aliases for bug bounty hunting

# Network scanning
alias nmap-quick='nmap -T4 -F'
alias nmap-full='nmap -T4 -A -v'
alias nmap-udp='nmap -sU -T4'
alias nmap-tcp='nmap -sS -T4'
alias masscan-quick='masscan -p1-1000 --rate=1000'

# Web application testing
alias dirb-common='dirb $1 /usr/share/wordlists/dirb/common.txt'
alias gobuster-dir='gobuster dir -u $1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
alias gobuster-dns='gobuster dns -d $1 -w /usr/share/wordlists/dnsmap.txt'
alias nikto-scan='nikto -h $1'
alias wpscan-basic='wpscan --url $1'

# Subdomain enumeration
alias subfinder-basic='subfinder -d $1'
alias assetfinder-basic='assetfinder --subs-only $1'
alias amass-basic='amass enum -d $1'

# SQL injection
alias sqlmap-basic='sqlmap -u $1 --batch --banner'
alias sqlmap-advanced='sqlmap -u $1 --batch --banner --dbs --tables --columns --dump'

# XSS testing
alias xsstrike-basic='python3 ~/tools/XSStrike/xsstrike.py -u $1'
alias dalfox-basic='dalfox url $1'

# OSINT
alias theharvester-basic='theHarvester -d $1 -b all'
alias sherlock-basic='python3 ~/tools/sherlock/sherlock.py $1'

# Utility
alias myip='curl ifconfig.me'
alias ports='netstat -tulanp'
alias listening='lsof -i -P -n | grep LISTEN'
alias processes='ps aux | grep -v grep | grep $1'
EOF

# Setup wordlists
print_status "Setting up wordlists..."
cd ~/wordlists
wget https://github.com/danielmiessler/SecLists/archive/master.zip
unzip master.zip
mv SecLists-master/* .
rmdir SecLists-master
rm master.zip

# Install VPN and anonymity tools
print_status "Installing VPN and anonymity tools..."
sudo apt install -y openvpn network-manager-openvpn network-manager-openvpn-gnome \
    tor torbrowser-launcher proxychains4 privoxy polipo redsocks \
    wireguard wireguard-tools resolvconf stunnel4 obfs4proxy \
    macchanger dnsutils bind9-dnsutils dnsmasq-base hostapd \
    iptables-persistent netfilter-persistent ufw gufw \
    bleachbit secure-delete wipe shred

# Install ProtonVPN
print_status "Installing ProtonVPN..."
wget -O protonvpn-stable-release_1.0.3-1_all.deb https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.3-1_all.deb
sudo dpkg -i protonvpn-stable-release_1.0.3-1_all.deb
sudo apt update
sudo apt install -y protonvpn-cli protonvpn

# Install additional Python packages for anonymity
print_status "Installing additional Python packages..."
pip3 install --user requests-html selenium webdriver-manager pyvirtualdisplay \
    pysocks requests[socks] stem fake-useragent rotating-proxies \
    python-proxy-rotator tor-python-easy aiohttp[speedups]

# Install VS Code (optional)
print_status "Installing Visual Studio Code..."
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/
sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/trusted.gpg.d/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
sudo apt update
sudo apt install -y code

# Final setup
print_status "Performing final setup..."
sudo updatedb
sudo apt autoremove -y
sudo apt autoclean

# Configure startup anonymity services
print_status "Configuring startup anonymity services..."
cat > ~/scripts/startup_anon.sh << 'EOF'
#!/bin/bash
# Startup Anonymity Configuration

print_status() {
    echo -e "\033[0;32m[+]\033[0m $1"
}

print_status "Configuring startup anonymity..."

# Disable potentially identifying services
sudo systemctl disable bluetooth
sudo systemctl disable cups
sudo systemctl disable avahi-daemon
sudo systemctl disable NetworkManager-wait-online

# Configure automatic MAC randomization on boot
sudo cat > /etc/systemd/system/mac-randomize.service << 'MACEOF'
[Unit]
Description=Randomize MAC addresses on boot
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'for iface in $(ls /sys/class/net/ | grep -v lo); do /usr/bin/macchanger -r $iface 2>/dev/null || true; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
MACEOF

sudo systemctl enable mac-randomize.service

# Configure DNS over HTTPS
print_status "Setting up DNS over HTTPS..."
sudo apt install -y cloudflared

# Create cloudflared config
sudo mkdir -p /etc/cloudflared
sudo cat > /etc/cloudflared/config.yml << 'DNSEOF'
proxy-dns: true
proxy-dns-port: 5053
proxy-dns-upstream:
  - https://1.1.1.1/dns-query
  - https://1.0.0.1/dns-query
  - https://8.8.8.8/dns-query
  - https://8.8.4.4/dns-query
DNSEOF

# Create systemd service for cloudflared
sudo cat > /etc/systemd/system/cloudflared.service << 'CLOUDEOF'
[Unit]
Description=cloudflared DNS over HTTPS proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/cloudflared --config /etc/cloudflared/config.yml
Restart=always
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
CLOUDEOF

sudo systemctl enable cloudflared.service

print_status "Startup anonymity configuration complete!"
EOF
chmod +x ~/scripts/startup_anon.sh

# Create comprehensive privacy hardening script
print_status "Creating comprehensive privacy hardening script..."
cat > ~/scripts/privacy_hardening.sh << 'EOF'
#!/bin/bash
# Comprehensive Privacy Hardening for Kali Linux

print_status() {
    echo -e "\033[0;32m[+]\033[0m $1"
}

print_warning() {
    echo -e "\033[1;33m[!]\033[0m $1"
}

print_status "Starting comprehensive privacy hardening..."

# Disable telemetry and reporting
print_status "Disabling telemetry and error reporting..."
sudo apt remove -y popularity-contest apport whoopsie
echo 'ENABLED=0' | sudo tee /etc/default/apport

# Harden kernel parameters
print_status "Hardening kernel parameters..."
sudo cat >> /etc/sysctl.conf << 'KERNELEOF'

# Privacy and security hardening
net.ipv4.tcp_timestamps = 0
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
KERNELEOF

sudo sysctl -p

# Configure Firefox for privacy
print_status "Configuring Firefox for privacy..."
FIREFOX_PROFILE_DIR=$(find ~/.mozilla/firefox -name "*.default*" -type d | head -1)
if [ -n "$FIREFOX_PROFILE_DIR" ]; then
    cat >> "$FIREFOX_PROFILE_DIR/user.js" << 'FIREFOXEOF'
// Privacy hardening for Firefox
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.donottrackheader.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("geo.enabled", false);
user_pref("media.navigator.enabled", false);
user_pref("webgl.disabled", true);
user_pref("javascript.options.wasm", false);
user_pref("dom.event.clipboardevents.enabled", false);
user_pref("media.autoplay.default", 5);
user_pref("network.cookie.cookieBehavior", 1);
user_pref("network.http.referer.XOriginPolicy", 2);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);
user_pref("browser.send_pings", false);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("dom.battery.enabled", false);
user_pref("device.sensors.enabled", false);
FIREFOXEOF
fi

# Disable IPv6 if not needed
print_status "Disabling IPv6..."
echo 'net.ipv6.conf.all.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.default.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv6.conf.lo.disable_ipv6 = 1' | sudo tee -a /etc/sysctl.conf

# Configure hosts file for ad blocking
print_status "Configuring hosts file for ad blocking..."
sudo wget -O /tmp/hosts https://someonewhocares.org/hosts/zero/hosts
sudo cp /etc/hosts /etc/hosts.backup
sudo cp /tmp/hosts /etc/hosts

# Set up automatic log cleaning
print_status "Setting up automatic log cleaning..."
sudo cat > /etc/cron.daily/privacy-cleanup << 'CLEANEOF'
#!/bin/bash
# Daily privacy cleanup

# Clear system logs older than 1 day
journalctl --vacuum-time=1d

# Clear user logs
rm -f /home/*/.bash_history
rm -f /home/*/.zsh_history
rm -f /home/*/.python_history
rm -f /home/*/.mysql_history

# Clear temporary files
rm -rf /tmp/*
rm -rf /var/tmp/*

# Clear thumbnail cache
rm -rf /home/*/.cache/thumbnails/*
rm -rf /home/*/.thumbnails/*

# Clear recent documents
rm -f /home/*/.recently-used
rm -f /home/*/.local/share/recently-used.xbel

# Clear browser caches
rm -rf /home/*/.cache/google-chrome/
rm -rf /home/*/.cache/chromium/
rm -rf /home/*/.cache/mozilla/
CLEANEOF

sudo chmod +x /etc/cron.daily/privacy-cleanup

# Configure secure memory allocation
print_status "Configuring secure memory..."
echo 'kernel.yama.ptrace_scope = 1' | sudo tee -a /etc/sysctl.conf

# Disable core dumps
print_status "Disabling core dumps..."
echo '* hard core 0' | sudo tee -a /etc/security/limits.conf
echo 'ProcessSizeMax=0' | sudo tee -a /etc/systemd/system.conf
echo 'DefaultLimitCORE=0' | sudo tee -a /etc/systemd/system.conf

# Configure umask for stricter permissions
print_status "Setting stricter file permissions..."
echo 'umask 077' | sudo tee -a /etc/profile

print_status "Privacy hardening complete!"
print_warning "Reboot required for all changes to take effect"
EOF
chmod +x ~/scripts/privacy_hardening.sh

# Update the main aliases to include anonymity tools
print_status "Updating aliases with anonymity tools..."
cat >> ~/scripts/aliases.sh << 'EOF'

# Anonymity and VPN aliases
alias anonsurf-start='sudo anonsurf start'
alias anonsurf-stop='sudo anonsurf stop'
alias tor-start='sudo systemctl start tor'
alias tor-stop='sudo systemctl stop tor'
alias tor-restart='sudo systemctl restart tor'
alias tor-status='sudo systemctl status tor'
alias protonvpn-connect='protonvpn-cli connect --fastest'
alias protonvpn-disconnect='protonvpn-cli disconnect'
alias check-ip='curl ifconfig.me'
alias check-tor='curl --proxy socks5://127.0.0.1:9050 https://check.torproject.org/api/ip'
alias change-mac='sudo macchanger -r'
alias proxychains='proxychains4'
alias anon-nmap='proxychains4 nmap'
alias anon-curl='proxychains4 curl'
alias anon-wget='proxychains4 wget'
alias clear-tracks='history -c && rm -f ~/.bash_history ~/.zsh_history'

# VirtualBox security aliases
alias vm-snapshot='echo "Run on HOST: VBoxManage snapshot KaliVM take"'
alias vm-restore='echo "Run on HOST: VBoxManage snapshot KaliVM restore"'
alias vm-list-snapshots='echo "Run on HOST: VBoxManage snapshot KaliVM list"'

# Security aliases
alias secure-delete='shred -vfz -n 3'
alias wipe-free-space='sudo dd if=/dev/zero of=/tmp/fillup bs=1M; rm /tmp/fillup'
alias random-hostname='sudo hostnamectl set-hostname kali-$(openssl rand -hex 4)'
EOF
print_info "Please log out and log back in to apply ZSH as your default shell."
# Display completion message with anonymity features
print_status "Setup complete!"
print_info "Please log out and log back in to apply ZSH as your default shell."
print_info ""
print_info "🔧 Useful directories:"
print_info "  Tools: ~/tools"
print_info "  Scripts: ~/scripts"
print_info "  Wordlists: ~/wordlists"
print_info ""
print_info "🛠️ Key installed tools:"
print_info "  - Subdomain enumeration: subfinder, assetfinder, amass, sublist3r"
print_info "  - Web scanning: nmap, masscan, gobuster, dirb, nikto"
print_info "  - Web app testing: burpsuite, zaproxy, sqlmap, xsstrike"
print_info "  - OSINT: theharvester, sherlock, spiderfoot"
print_info "  - Programming: Python, Go, Node.js, Ruby, Java, PHP"
print_info ""
print_info "🔐 Anonymity & VPN tools:"
print_info "  - VPN: ProtonVPN CLI, OpenVPN, WireGuard"
print_info "  - Tor: Tor service, Torbrowser, ProxyChains4"
print_info "  - Anonymity: AnonSurf, Kalitorify, MAC changer"
print_info "  - Traffic: Cover traffic generator, IP rotator"
print_info ""
print_info "📱 Key scripts:"
print_info "  - VPN Manager: ~/scripts/vpn_manager.sh"
print_info "  - Anonymous Recon: ~/scripts/anon_recon.sh"
print_info "  - IP Rotator: ~/scripts/ip_rotator.sh"
print_info "  - Traffic Analysis: ~/scripts/traffic_analysis.py"
print_info "  - Privacy Hardening: ~/scripts/privacy_hardening.sh"
print_info "  - VM Snapshots Guide: ~/scripts/vm_snapshots.sh"
print_info "  - VirtualBox Anon Setup: ~/scripts/vbox_anon_setup.sh"
print_info ""
print_info "🚀 Quick start commands:"
print_info "  source ~/scripts/aliases.sh                 # Load useful aliases"
print_info "  ~/scripts/vpn_manager.sh                    # Start VPN/Tor management"
print_info "  ~/scripts/vbox_anon_setup.sh               # Configure VirtualBox anonymity"
print_info "  ~/scripts/privacy_hardening.sh             # Harden system for privacy"
print_info "  ~/scripts/ip_rotator.sh check              # Validate anonymity setup"
print_info ""
print_warning "🔒 IMPORTANT VirtualBox Security Steps:"
print_warning "1. DO NOT install VirtualBox Guest Additions (leaks host info)"
print_warning "2. Use NAT networking only (never Bridged mode)"
print_warning "3. Disable shared folders, clipboard, and USB"
print_warning "4. Take snapshots before operations, restore after"
print_warning "5. Generate new MAC addresses regularly"
print_warning "6. Never save credentials permanently on VM"
print_warning ""
print_warning "⚠️ Configuration needed:"
print_warning "- Configure API keys for tools (Shodan, SecurityTrails, etc.)"
print_warning "- Set up ProtonVPN account and login: protonvpn-cli login"
print_warning "- Run privacy hardening script for maximum anonymity"
print_warning "- Configure browser proxy settings for Tor (SOCKS5 127.0.0.1:9050)"
print_warning ""
print_info "🎯 Anonymity workflow:"
print_info "1. Take VM snapshot"
print_info "2. Start VPN/Tor: ~/scripts/vpn_manager.sh"
print_info "3. Change MAC address: sudo macchanger -r eth0"
print_info "4. Validate anonymity: ~/scripts/ip_rotator.sh check"
print_info "5. Run reconnaissance: ~/scripts/anon_recon.sh target.com --tor"
print_info "6. Clear tracks: ~/scripts/vpn_manager.sh → option 13"
print_info "7. Restore VM snapshot"
print_info ""
print_info "📚 Additional resources:"
print_info "  - Burp extensions: ~/scripts/burp_extensions.sh"
print_info "  - Secure communications: ~/scripts/secure_comms.sh"
print_info "  - Startup anonymity: ~/scripts/startup_anon.sh"
print_info ""

echo -e "\n${GREEN}🔒 Stay anonymous, stay secure! Happy bug hunting! 🐛💰${NC}"
echo -e "${YELLOW}Remember: Security through obscurity is not security at all.${NC}"
echo -e "${YELLOW}Always use proper OPSEC and multiple layers of anonymity.${NC}"
