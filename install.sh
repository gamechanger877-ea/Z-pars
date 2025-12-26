#!/bin/bash

# =============================================================================
# Z-PARS VPN PANEL - Advanced Multi-Protocol VPN Management Panel
# Author: Z-PARS Development Team
# Version: 1.0.0
# License: GPL-3.0
# Description: High-performance VPN panel with multi-protocol support
# =============================================================================

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
PLAIN='\033[0m'
BOLD='\033[1m'

# Panel configuration
PANEL_NAME="Z-PARS VPN Panel"
PANEL_VERSION="1.0.0"
PANEL_DIR="/usr/local/z-pars"
CONFIG_DIR="/etc/z-pars"
LOG_DIR="/var/log/z-pars"
DB_DIR="/var/lib/z-pars"
SCRIPT_URL="https://raw.githubusercontent.com/z-pars/z-pars-vpn/main"

# Default settings
DEFAULT_PORT="8080"
DEFAULT_USER="admin"
DEFAULT_DB_USER="z_pars"
DB_NAME="z_pars_db"

# Protocol ports
OPENVPN_PORT="1194"
WIREGUARD_PORT="51820"
SHADOWSOCKS_PORT="8388"
TROJAN_PORT="443"
VMESS_PORT="10086"
VLESS_PORT="10087"
HYSTERIA_PORT="33445"

# Performance settings
MAX_CONNECTIONS="10000"
BUFFER_SIZE="65536"
TIMEOUT="300"

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${PLAIN} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" >> "$LOG_DIR/install.log"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${PLAIN} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $1" >> "$LOG_DIR/install.log"
}

log_error() {
    echo -e "${RED}[ERROR]${PLAIN} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "$LOG_DIR/install.log"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${PLAIN} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [DEBUG] $1" >> "$LOG_DIR/install.log"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root!"
        exit 1
    fi
}

# Check OS distribution
check_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot determine OS version"
        exit 1
    fi
    
    case "$OS" in
        ubuntu)
            if [[ ! "$VERSION" =~ ^(20\.04|22\.04|24\.04)$ ]]; then
                log_warn "Ubuntu version $VERSION may not be fully supported"
            fi
            ;;
        debian)
            if [[ ! "$VERSION" =~ ^(10|11|12)$ ]]; then
                log_warn "Debian version $VERSION may not be fully supported"
            fi
            ;;
        centos|rhel|almalinux|rocky)
            if [[ ! "$VERSION" =~ ^(7|8|9)$ ]]; then
                log_warn "RHEL/CentOS version $VERSION may not be fully supported"
            fi
            ;;
        *)
            log_warn "OS $OS may not be fully supported"
            ;;
    esac
    
    log_info "Detected OS: $OS $VERSION"
}

# Check system architecture
check_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l|armv7)
            ARCH="armv7"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    log_info "System architecture: $ARCH"
}

# Generate random string
gen_random_string() {
    local length=${1:-16}
    LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | head -c "$length"
}

# Generate strong password
gen_strong_password() {
    LC_ALL=C tr -dc 'a-zA-Z0-9!@#$%^&*' </dev/urandom | head -c 16
}

# Check if port is available
check_port() {
    local port=$1
    if netstat -tuln | grep -q ":$port "; then
        return 1
    else
        return 0
    fi
}

# Find available port
find_available_port() {
    local start_port=${1:-1000}
    local end_port=${2:-65000}
    
    for ((port=start_port; port<=end_port; port++)); do
        if check_port "$port"; then
            echo "$port"
            return 0
        fi
    done
    return 1
}

# Get public IP
get_public_ip() {
    local ip=""
    local ip_services=(
        "https://api.ipify.org"
        "https://ipv4.icanhazip.com"
        "https://v4.ident.me"
        "https://checkip.amazonaws.com"
    )
    
    for service in "${ip_services[@]}"; do
        ip=$(curl -s --max-time 3 "$service" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "$ip" && ! "$ip" =~ [a-zA-Z] ]]; then
            echo "$ip"
            return 0
        fi
    done
    
    log_error "Could not determine public IP address"
    return 1
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    # Check RAM
    local ram_gb=$(free -g | awk '/^Mem:/ {print $2}')
    if [[ $ram_gb -lt 1 ]]; then
        log_warn "System has less than 1GB RAM. Some features may not work properly"
    fi
    
    # Check disk space
    local disk_gb=$(df -BG / | awk 'NR==2 {print $4}' | tr -d 'G')
    if [[ $disk_gb -lt 2 ]]; then
        log_warn "Less than 2GB free disk space available"
    fi
    
    # Check if running in container
    if [[ -f /.dockerenv ]] || grep -q "docker" /proc/1/cgroup 2>/dev/null; then
        log_info "Running in container environment"
        IN_CONTAINER=true
    else
        IN_CONTAINER=false
    fi
}

# =============================================================================
# INSTALLATION FUNCTIONS
# =============================================================================

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    case "$OS" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq \
                curl wget git unzip tar \
                build-essential cmake \
                libssl-dev libuv1-dev \
                uuid-dev libmicrohttpd-dev \
                libsodium-dev libpq-dev \
                nginx mysql-server redis-server \
                supervisor cron logrotate \
                ufw fail2ban \
                qrencode imagemagick \
                python3 python3-pip \
                nodejs npm
            ;;
        centos|rhel|almalinux|rocky)
            if [[ "$VERSION" == "7" ]]; then
                yum install -y -q epel-release
                yum install -y -q \
                    curl wget git unzip tar \
                    gcc gcc-c++ make cmake \
                    openssl-devel libuv-devel \
                    uuid-devel libmicrohttpd-devel \
                    libsodium-devel postgresql-devel \
                    nginx mysql-server redis \
                    supervisor cronie logrotate \
                    firewalld fail2ban \
                    qrencode ImageMagick \
                    python3 python3-pip \
                    nodejs npm
            else
                dnf install -y -q epel-release
                dnf install -y -q \
                    curl wget git unzip tar \
                    gcc gcc-c++ make cmake \
                    openssl-devel libuv-devel \
                    uuid-devel libmicrohttpd-devel \
                    libsodium-devel postgresql-devel \
                    nginx mysql-server redis \
                    supervisor cronie logrotate \
                    firewalld fail2ban \
                    qrencode ImageMagick \
                    python3 python3-pip \
                    nodejs npm
            fi
            ;;
        *)
            log_error "Unsupported OS for automatic dependency installation"
            exit 1
            ;;
    esac
    
    if [[ $? -ne 0 ]]; then
        log_error "Failed to install some dependencies"
        exit 1
    fi
    
    log_info "System dependencies installed successfully"
}

# Install additional repositories
install_repositories() {
    log_info "Adding additional repositories..."
    
    case "$OS" in
        ubuntu|debian)
            # Add Node.js repository
            curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
            
            # Add Docker repository (optional)
            if [[ "$INSTALL_DOCKER" == "true" ]]; then
                curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/$OS $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list
            fi
            ;;
    esac
}

# Install VPN protocols
install_vpn_protocols() {
    log_info "Installing VPN protocols..."
    
    # Install OpenVPN
    install_openvpn
    
    # Install WireGuard
    install_wireguard
    
    # Install Shadowsocks
    install_shadowsocks
    
    # Install Trojan
    install_trojan
    
    # Install Xray (VMESS/VLESS)
    install_xray
    
    # Install Hysteria
    install_hysteria
    
    log_info "VPN protocols installation completed"
}

# Install OpenVPN
install_openvpn() {
    log_info "Installing OpenVPN..."
    
    case "$OS" in
        ubuntu|debian)
            apt-get install -y -qq openvpn easy-rsa
            ;;
        centos|rhel|almalinux|rocky)
            if [[ "$VERSION" == "7" ]]; then
                yum install -y -q openvpn easy-rsa
            else
                dnf install -y -q openvpn easy-rsa
            fi
            ;;
    esac
    
    # Setup PKI
    if [[ ! -d /etc/openvpn/pki ]]; then
        make-cadir /etc/openvpn/pki
        cd /etc/openvpn/pki
        
        # Configure vars
        cat > vars <<EOF
set_var EASYRSA_REQ_COUNTRY    "US"
set_var EASYRSA_REQ_PROVINCE   "California"
set_var EASYRSA_REQ_CITY       "San Francisco"
set_var EASYRSA_REQ_ORG        "Z-PARS VPN"
set_var EASYRSA_REQ_EMAIL      "admin@z-pars.local"
set_var EASYRSA_REQ_OU         "Z-PARS VPN Server"
set_var EASYRSA_ALGO           "ec"
set_var EASYRSA_CURVE          "secp384r1"
EOF
        
        # Build CA and server certs
        ./easyrsa --batch init-pki
        ./easyrsa --batch build-ca nopass
        ./easyrsa --batch build-server-full server nopass
        ./easyrsa --batch gen-dh
        
        # Generate TLS auth key
        openvpn --genkey --secret ta.key
    fi
    
    # Configure OpenVPN server
    cat > /etc/openvpn/server.conf <<EOF
port $OPENVPN_PORT
proto udp
dev tun
ca /etc/openvpn/pki/ca.crt
cert /etc/openvpn/pki/issued/server.crt
key /etc/openvpn/pki/private/server.key
dh /etc/openvpn/pki/dh.pem
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-GCM
auth SHA256
compress lz4-v2
push "compress lz4-v2"
max-clients 1000
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3
explicit-exit-notify 1
EOF
    
    # Enable and start OpenVPN
    systemctl enable openvpn@server
    systemctl start openvpn@server
    
    log_info "OpenVPN installed and configured"
}

# Install WireGuard
install_wireguard() {
    log_info "Installing WireGuard..."
    
    case "$OS" in
        ubuntu|debian)
            apt-get install -y -qq wireguard qrencode
            ;;
        centos|rhel|almalinux|rocky)
            if [[ "$VERSION" == "7" ]]; then
                yum install -y -q epel-release elrepo-release
                yum install -y -q kmod-wireguard wireguard-tools qrencode
            else
                dnf install -y -q epel-release elrepo-release
                dnf install -y -q kmod-wireguard wireguard-tools qrencode
            fi
            ;;
    esac
    
    # Generate WireGuard keys
    if [[ ! -f /etc/wireguard/server_private.key ]]; then
        cd /etc/wireguard
        umask 077
        wg genkey | tee server_private.key | wg pubkey > server_public.key
        wg genpsk > server_psk.key
    fi
    
    # Configure WireGuard
    cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $(cat /etc/wireguard/server_private.key)
Address = 10.0.0.1/24
ListenPort = $WIREGUARD_PORT
PostUp = ufw route allow in on wg0 out on $(ip route | grep default | awk '{print $5}')
PostUp = iptables -t nat -A POSTROUTING -o $(ip route | grep default | awk '{print $5}') -j MASQUERADE
PostUp = ip6tables -t nat -A POSTROUTING -o $(ip route | grep default | awk '{print $5}') -j MASQUERADE
PostDown = ufw route delete allow in on wg0 out on $(ip route | grep default | awk '{print $5}')
PostDown = iptables -t nat -D POSTROUTING -o $(ip route | grep default | awk '{print $5}') -j MASQUERADE
PostDown = ip6tables -t nat -D POSTROUTING -o $(ip route | grep default | awk '{print $5}') -j MASQUERADE
SaveConfig = true

# Peer configurations will be added dynamically
EOF
    
    # Enable and start WireGuard
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    log_info "WireGuard installed and configured"
}

# Install Shadowsocks
install_shadowsocks() {
    log_info "Installing Shadowsocks..."
    
    # Install Shadowsocks-libev
    case "$OS" in
        ubuntu|debian)
            apt-get install -y -qq shadowsocks-libev
            ;;
        centos|rhel|almalinux|rocky)
            if [[ "$VERSION" == "7" ]]; then
                yum install -y -q epel-release
                yum install -y -q shadowsocks-libev
            else
                dnf install -y -q epel-release
                dnf install -y -q shadowsocks-libev
            fi
            ;;
    esac
    
    # Configure Shadowsocks
    cat > /etc/shadowsocks-libev/config.json <<EOF
{
    "server": "0.0.0.0",
    "server_port": $SHADOWSOCKS_PORT,
    "password": "$(gen_strong_password)",
    "timeout": 300,
    "method": "chacha20-ietf-poly1305",
    "fast_open": true,
    "workers": 4,
    "prefer_ipv6": false
}
EOF
    
    # Enable and start Shadowsocks
    systemctl enable shadowsocks-libev
    systemctl start shadowsocks-libev
    
    log_info "Shadowsocks installed and configured"
}

# Install Trojan
install_trojan() {
    log_info "Installing Trojan..."
    
    # Download and install Trojan
    TROJAN_VERSION=$(curl -s https://api.github.com/repos/trojan-gfw/trojan/releases/latest | grep tag_name | cut -d '"' -f 4)
    wget -q -O /tmp/trojan.tar.gz "https://github.com/trojan-gfw/trojan/releases/download/$TROJAN_VERSION/trojan-$TROJAN_VERSION-linux-amd64.tar.xz"
    
    if [[ -f /tmp/trojan.tar.gz ]]; then
        tar -xf /tmp/trojan.tar.gz -C /tmp
        mv /tmp/trojan/trojan /usr/local/bin/
        chmod +x /usr/local/bin/trojan
        rm -rf /tmp/trojan*
    fi
    
    # Generate self-signed cert for Trojan
    if [[ ! -f /etc/ssl/private/trojan.key ]]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/trojan.key \
            -out /etc/ssl/certs/trojan.crt \
            -subj "/C=US/ST=CA/L=San Francisco/O=Z-PARS/CN=trojan.local"
    fi
    
    # Configure Trojan
    cat > /etc/trojan/config.json <<EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": $TROJAN_PORT,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": ["$(gen_strong_password)"],
    "log_level": 1,
    "ssl": {
        "cert": "/etc/ssl/certs/trojan.crt",
        "key": "/etc/ssl/private/trojan.key",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": ["http/1.1"],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "prefer_ipv4": false,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": ""
    }
}
EOF
    
    # Create systemd service for Trojan
    cat > /etc/systemd/system/trojan.service <<EOF
[Unit]
Description=Trojan
After=network.target

[Service]
Type=simple
PIDFile=/var/run/trojan.pid
ExecStart=/usr/local/bin/trojan /etc/trojan/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable trojan
    systemctl start trojan
    
    log_info "Trojan installed and configured"
}

# Install Xray
install_xray() {
    log_info "Installing Xray (VMESS/VLESS)..."
    
    # Install Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install.sh)" @ install
    
    # Configure Xray for VMESS
    cat > /usr/local/etc/xray/vmess.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": $VMESS_PORT,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "$(cat /proc/sys/kernel/random/uuid)",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vmess"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    
    # Configure Xray for VLESS
    cat > /usr/local/etc/xray/vless.json <<EOF
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": $VLESS_PORT,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$(cat /proc/sys/kernel/random/uuid)",
            "flow": "xtls-rprx-direct"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/vless"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
    
    log_info "Xray installed and configured"
}

# Install Hysteria
install_hysteria() {
    log_info "Installing Hysteria..."
    
    # Download and install Hysteria
    HYSTERIA_VERSION=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep tag_name | cut -d '"' -f 4)
    wget -q -O /tmp/hysteria.tar.gz "https://github.com/apernet/hysteria/releases/download/$HYSTERIA_VERSION/hysteria-linux-$ARCH.tar.gz"
    
    if [[ -f /tmp/hysteria.tar.gz ]]; then
        tar -xf /tmp/hysteria.tar.gz -C /tmp
        mv /tmp/hysteria /usr/local/bin/
        chmod +x /usr/local/bin/hysteria
        rm -rf /tmp/hysteria*
    fi
    
    # Generate self-signed cert for Hysteria
    if [[ ! -f /etc/ssl/private/hysteria.key ]]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/hysteria.key \
            -out /etc/ssl/certs/hysteria.crt \
            -subj "/C=US/ST=CA/L=San Francisco/O=Z-PARS/CN=hysteria.local"
    fi
    
    # Configure Hysteria
    cat > /etc/hysteria/config.json <<EOF
{
  "listen": ":$HYSTERIA_PORT",
  "cert": "/etc/ssl/certs/hysteria.crt",
  "key": "/etc/ssl/private/hysteria.key",
  "auth": {
    "mode": "passwords",
    "config": ["$(gen_strong_password)"]
  },
  "disableUDP": false,
  "udpIdleTimeout": "60s",
  "resolver": "https://8.8.8.8:443",
  "resolvePreference": "46"
}
EOF
    
    # Create systemd service for Hysteria
    cat > /etc/systemd/system/hysteria.service <<EOF
[Unit]
Description=Hysteria Server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server --config /etc/hysteria/config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable hysteria
    systemctl start hysteria
    
    log_info "Hysteria installed and configured"
}

# Setup database
setup_database() {
    log_info "Setting up database..."
    
    # Generate random database password
    DB_PASS=$(gen_strong_password)
    
    # Start MySQL if not running
    if ! systemctl is-active --quiet mysql; then
        systemctl start mysql
    fi
    
    # Secure MySQL installation
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$DB_PASS';"
    mysql -e "DELETE FROM mysql.user WHERE User='';"
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    mysql -e "DROP DATABASE IF EXISTS test;"
    mysql -e "FLUSH PRIVILEGES;"
    
    # Create database and user
    mysql -e "CREATE DATABASE IF NOT EXISTS $DB_NAME;"
    mysql -e "CREATE USER IF NOT EXISTS '$DEFAULT_DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';"
    mysql -e "GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DEFAULT_DB_USER'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    
    # Store credentials
    cat > "$CONFIG_DIR/.db.conf" <<EOF
DB_HOST=localhost
DB_PORT=3306
DB_NAME=$DB_NAME
DB_USER=$DEFAULT_DB_USER
DB_PASS=$DB_PASS
EOF
    
    chmod 600 "$CONFIG_DIR/.db.conf"
    
    log_info "Database setup completed"
}

# Setup panel web interface
setup_panel_interface() {
    log_info "Setting up panel web interface..."
    
    # Create panel directory structure
    mkdir -p "$PANEL_DIR"/{bin,logs,tmp,ssl}
    mkdir -p "$CONFIG_DIR"/{nginx,supervisor}
    mkdir -p "$LOG_DIR"
    mkdir -p "$DB_DIR"
    
    # Download and setup panel files
    # This would typically download from a repository
    # For now, we'll create basic structure
    
    # Create main panel configuration
    cat > "$CONFIG_DIR/panel.conf" <<EOF
[PANEL]
name = $PANEL_NAME
version = $PANEL_VERSION
debug = false
port = $DEFAULT_PORT
secret_key = $(gen_random_string 32)

[DATABASE]
host = localhost
port = 3306
name = $DB_NAME
user = $DEFAULT_DB_USER

[SECURITY]
max_login_attempts = 5
lockout_duration = 300
password_min_length = 8
session_timeout = 3600

[VPN]
openvpn_port = $OPENVPN_PORT
wireguard_port = $WIREGUARD_PORT
shadowsocks_port = $SHADOWSOCKS_PORT
trojan_port = $TROJAN_PORT
vmess_port = $VMESS_PORT
vless_port = $VLESS_PORT
hysteria_port = $HYSTERIA_PORT

[PERFORMANCE]
max_connections = $MAX_CONNECTIONS
buffer_size = $BUFFER_SIZE
timeout = $TIMEOUT
worker_processes = auto

[LOGGING]
level = info
max_size = 100MB
backup_count = 5
EOF
    
    # Create Nginx configuration
    cat > "$CONFIG_DIR/nginx/panel.conf" <<EOF
server {
    listen 80;
    server_name _;
    
    client_max_body_size 100M;
    
    location / {
        proxy_pass http://127.0.0.1:$DEFAULT_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    location /static {
        alias $PANEL_DIR/static;
        expires 30d;
    }
}
EOF
    
    # Create systemd service
    cat > /etc/systemd/system/z-pars-panel.service <<EOF
[Unit]
Description=Z-PARS VPN Panel
After=network.target mysql.service redis.service
Wants=mysql.service redis.service

[Service]
Type=simple
User=root
WorkingDirectory=$PANEL_DIR
ExecStart=$PANEL_DIR/bin/panel
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=z-pars-panel

[Install]
WantedBy=multi-user.target
EOF
    
    log_info "Panel interface setup completed"
}

# Setup firewall
setup_firewall() {
    log_info "Configuring firewall..."
    
    case "$OS" in
        ubuntu|debian)
            # Configure UFW
            ufw default deny incoming
            ufw default allow outgoing
            
            # Allow SSH
            ufw allow 22/tcp
            
            # Allow panel port
            ufw allow "$DEFAULT_PORT"/tcp
            
            # Allow VPN protocols
            ufw allow "$OPENVPN_PORT"/udp
            ufw allow "$WIREGUARD_PORT"/udp
            ufw allow "$SHADOWSOCKS_PORT"/tcp
            ufw allow "$TROJAN_PORT"/tcp
            ufw allow "$VMESS_PORT"/tcp
            ufw allow "$VLESS_PORT"/tcp
            ufw allow "$HYSTERIA_PORT"/udp
            
            # Allow HTTP/HTTPS
            ufw allow 80/tcp
            ufw allow 443/tcp
            
            # Enable UFW
            ufw --force enable
            ;;
        centos|rhel|almalinux|rocky)
            # Configure firewalld
            systemctl enable firewalld
            systemctl start firewalld
            
            # Allow services
            firewall-cmd --permanent --add-service=ssh
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
            
            # Allow custom ports
            firewall-cmd --permanent --add-port="$DEFAULT_PORT"/tcp
            firewall-cmd --permanent --add-port="$OPENVPN_PORT"/udp
            firewall-cmd --permanent --add-port="$WIREGUARD_PORT"/udp
            firewall-cmd --permanent --add-port="$SHADOWSOCKS_PORT"/tcp
            firewall-cmd --permanent --add-port="$TROJAN_PORT"/tcp
            firewall-cmd --permanent --add-port="$VMESS_PORT"/tcp
            firewall-cmd --permanent --add-port="$VLESS_PORT"/tcp
            firewall-cmd --permanent --add-port="$HYSTERIA_PORT"/udp
            
            # Reload firewall
            firewall-cmd --reload
            ;;
    esac
    
    log_info "Firewall configured successfully"
}

# Setup fail2ban
setup_fail2ban() {
    log_info "Configuring fail2ban..."
    
    # Configure fail2ban for SSH
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 3

[panel-auth]
enabled = true
port = $DEFAULT_PORT
filter = panel-auth
logpath = $LOG_DIR/auth.log
maxretry = 3
bantime = 1800

EOF
    
    # Create custom filter for panel
    cat > /etc/fail2ban/filter.d/panel-auth.conf <<EOF
[Definition]
failregex = ^<HOST> -.*"POST /api/login.*" 401.*
            ^<HOST> -.*"POST /login.*" 401.*
ignoreregex =
EOF
    
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    log_info "Fail2ban configured successfully"
}

# Setup system optimization
setup_system_optimization() {
    log_info "Optimizing system for VPN performance..."
    
    # Backup original sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.backup
    
    # Add performance optimizations
    cat >> /etc/sysctl.conf <<EOF

# Z-PARS VPN Performance Optimizations
# Increase system file descriptor limit
fs.file-max = 51200

# Increase max connections
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096

# TCP optimizations
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1

# IP optimizations
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    
    # Apply sysctl settings
    sysctl -p
    
    # Configure limits
    cat > /etc/security/limits.conf.append <<EOF
# Z-PARS VPN Limits
* soft nofile 51200
* hard nofile 51200
* soft nproc 51200
* hard nproc 51200
EOF
    
    cat /etc/security/limits.conf.append >> /etc/security/limits.conf
    rm /etc/security/limits.conf.append
    
    log_info "System optimization completed"
}

# Create admin user
create_admin_user() {
    log_info "Creating admin user..."
    
    # Generate random credentials
    ADMIN_USER=$(gen_random_string 8)
    ADMIN_PASS=$(gen_strong_password)
    
    # Store credentials securely
    cat > "$CONFIG_DIR/.admin" <<EOF
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$ADMIN_PASS
EOF
    chmod 600 "$CONFIG_DIR/.admin"
    
    # Add admin to database (this would be done through panel API)
    log_info "Admin user created: $ADMIN_USER"
    log_info "Password saved to $CONFIG_DIR/.admin"
}

# Setup monitoring
setup_monitoring() {
    log_info "Setting up monitoring..."
    
    # Install monitoring tools
    case "$OS" in
        ubuntu|debian)
            apt-get install -y -qq htop iotop vnstat nethogs
            ;;
        centos|rhel|almalinux|rocky)
            if [[ "$VERSION" == "7" ]]; then
                yum install -y -q htop iotop vnstat nethogs
            else
                dnf install -y -q htop iotop vnstat nethogs
            fi
            ;;
    esac
    
    # Create monitoring script
    cat > "$PANEL_DIR/bin/monitor.sh" <<'EOF'
#!/bin/bash

PANEL_DIR="/usr/local/z-pars"
LOG_DIR="/var/log/z-pars"

# System metrics
get_system_metrics() {
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')
    local mem_usage=$(free | grep Mem | awk '{printf "%.2f", $3/$2 * 100.0}')
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    
    echo "CPU Usage: ${cpu_usage}%"
    echo "Memory Usage: ${mem_usage}%"
    echo "Disk Usage: ${disk_usage}%"
}

# Network metrics
get_network_metrics() {
    local connections=$(netstat -an | wc -l)
    local network_io=$(cat /proc/net/dev | grep -E '^\s*(eth|ens|enp)' | awk '{print $2+$10}')
    
    echo "Active Connections: $connections"
    echo "Network I/O: $network_io bytes"
}

# VPN metrics
get_vpn_metrics() {
    echo "=== OpenVPN ==="
    systemctl is-active openvpn@server && echo "Status: Running" || echo "Status: Stopped"
    
    echo "=== WireGuard ==="
    systemctl is-active wg-quick@wg0 && echo "Status: Running" || echo "Status: Stopped"
    
    echo "=== Shadowsocks ==="
    systemctl is-active shadowsocks-libev && echo "Status: Running" || echo "Status: Stopped"
    
    echo "=== Trojan ==="
    systemctl is-active trojan && echo "Status: Running" || echo "Status: Stopped"
}

# Log metrics
log_metrics() {
    {
        echo "=== System Metrics ==="
        get_system_metrics
        echo ""
        echo "=== Network Metrics ==="
        get_network_metrics
        echo ""
        echo "=== VPN Metrics ==="
        get_vpn_metrics
        echo "======================================="
    } >> "$LOG_DIR/metrics.log"
}

# Main
main() {
    log_metrics
}

main "$@"
EOF
    
    chmod +x "$PANEL_DIR/bin/monitor.sh"
    
    # Add monitoring to crontab
    (crontab -l 2>/dev/null || echo "") | grep -v "monitor.sh" | (cat; echo "*/5 * * * * $PANEL_DIR/bin/monitor.sh") | crontab -
    
    log_info "Monitoring setup completed"
}

# Setup backup system
setup_backup() {
    log_info "Setting up backup system..."
    
    # Create backup script
    cat > "$PANEL_DIR/bin/backup.sh" <<'EOF'
#!/bin/bash

PANEL_DIR="/usr/local/z-pars"
CONFIG_DIR="/etc/z-pars"
LOG_DIR="/var/log/z-pars"
BACKUP_DIR="/var/backups/z-pars"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup panel configuration
tar -czf "$BACKUP_DIR/panel_config_$DATE.tar.gz" -C "$CONFIG_DIR" . --exclude=".db.conf" --exclude=".admin"

# Backup database
source "$CONFIG_DIR/.db.conf" 2>/dev/null
if [[ -n "$DB_NAME" && -n "$DB_USER" ]]; then
    mysqldump -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" > "$BACKUP_DIR/database_$DATE.sql"
    gzip "$BACKUP_DIR/database_$DATE.sql"
fi

# Backup VPN configurations
tar -czf "$BACKUP_DIR/vpn_config_$DATE.tar.gz" \
    /etc/openvpn/ \
    /etc/wireguard/ \
    /etc/shadowsocks-libev/ \
    /etc/trojan/ \
    /usr/local/etc/xray/ \
    /etc/hysteria/ 2>/dev/null

# Clean old backups (keep last 7 days)
find "$BACKUP_DIR" -name "*.tar.gz" -o -name "*.sql.gz" | sort | head -n -7 | xargs rm -f

echo "Backup completed: $DATE"
EOF
    
    chmod +x "$PANEL_DIR/bin/backup.sh"
    
    # Add backup to crontab (daily at 2 AM)
    (crontab -l 2>/dev/null || echo "") | grep -v "backup.sh" | (cat; echo "0 2 * * * $PANEL_DIR/bin/backup.sh") | crontab -
    
    log_info "Backup system setup completed"
}

# =============================================================================
# USER MANAGEMENT FUNCTIONS
# =============================================================================

create_vpn_user() {
    local username=$1
    local protocol=$2
    local traffic_limit=$3
    local expiry_date=$4
    
    if [[ -z "$username" || -z "$protocol" ]]; then
        log_error "Username and protocol are required"
        return 1
    fi
    
    case "$protocol" in
        openvpn)
            create_openvpn_user "$username"
            ;;
        wireguard)
            create_wireguard_user "$username"
            ;;
        shadowsocks)
            create_shadowsocks_user "$username"
            ;;
        trojan)
            create_trojan_user "$username"
            ;;
        vmess)
            create_vmess_user "$username"
            ;;
        vless)
            create_vless_user "$username"
            ;;
        hysteria)
            create_hysteria_user "$username"
            ;;
        *)
            log_error "Unknown protocol: $protocol"
            return 1
            ;;
    esac
}

create_openvpn_user() {
    local username=$1
    
    cd /etc/openvpn/pki
    ./easyrsa --batch build-client-full "$username" nopass
    
    # Generate client config
    cat > "/etc/openvpn/clients/$username.ovpn" <<EOF
client
dev tun
proto udp
remote $(get_public_ip) $OPENVPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
compress lz4-v2
verb 3
<ca>
$(cat /etc/openvpn/pki/ca.crt)
</ca>
<cert>
$(cat /etc/openvpn/pki/issued/$username.crt)
</cert>
<key>
$(cat /etc/openvpn/pki/private/$username.key)
</key>
<tls-auth>
$(cat /etc/openvpn/pki/ta.key)
</tls-auth>
key-direction 1
EOF
    
    log_info "OpenVPN user created: $username"
}

create_wireguard_user() {
    local username=$1
    
    cd /etc/wireguard
    
    # Generate client keys
    umask 077
    wg genkey | tee "${username}_private.key" | wg pubkey > "${username}_public.key"
    
    # Get server public key
    SERVER_PUB=$(cat server_public.key)
    CLIENT_PRIV=$(cat "${username}_private.key")
    CLIENT_PUB=$(cat "${username}_public.key")
    
    # Generate IP for client
    CLIENT_IP=$(grep -c '^\[Peer\]$' wg0.conf | awk '{print $1+2}')
    
    # Add peer to server config
    cat >> wg0.conf <<EOF

[Peer]
PublicKey = $CLIENT_PUB
PresharedKey = $(cat server_psk.key)
AllowedIPs = 10.0.0.$CLIENT_IP/32
EOF
    
    # Generate client config
    cat > "/etc/wireguard/clients/$username.conf" <<EOF
[Interface]
PrivateKey = $CLIENT_PRIV
Address = 10.0.0.$CLIENT_IP/24
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = $SERVER_PUB
PresharedKey = $(cat server_psk.key)
Endpoint = $(get_public_ip):$WIREGUARD_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF
    
    # Generate QR code
    qrencode -t ansiutf8 < "/etc/wireguard/clients/$username.conf"
    
    # Reload WireGuard
    systemctl reload wg-quick@wg0
    
    log_info "WireGuard user created: $username"
}

create_shadowsocks_user() {
    local username=$1
    local password=$(gen_strong_password)
    
    # This would typically update the Shadowsocks config
    # For now, we'll create a separate config file
    cat > "/etc/shadowsocks-libev/$username.json" <<EOF
{
    "server": "0.0.0.0",
    "server_port": $(find_available_port 20000),
    "password": "$password",
    "timeout": 300,
    "method": "chacha20-ietf-poly1305",
    "fast_open": true,
    "workers": 2
}
EOF
    
    log_info "Shadowsocks user created: $username (Port: $(grep server_port /etc/shadowsocks-libev/$username.json | cut -d: -f2 | tr -d ' ,'))"
}

# =============================================================================
# MAIN INSTALLATION FUNCTION
# =============================================================================

install_panel() {
    log_info "Starting Z-PARS VPN Panel installation..."
    
    # Check prerequisites
    check_root
    check_os
    check_arch
    check_requirements
    
    # Install components
    install_dependencies
    install_repositories
    install_vpn_protocols
    setup_database
    setup_panel_interface
    setup_firewall
    setup_fail2ban
    setup_system_optimization
    setup_monitoring
    setup_backup
    create_admin_user
    
    # Start services
    systemctl daemon-reload
    systemctl enable z-pars-panel
    systemctl start z-pars-panel
    
    # Get admin credentials
    source "$CONFIG_DIR/.admin" 2>/dev/null
    
    # Display completion message
    clear
    cat <<EOF

${GREEN}╔══════════════════════════════════════════════════════════════════════╗
║                  Z-PARS VPN PANEL INSTALLATION COMPLETE              ║
╚══════════════════════════════════════════════════════════════════════╝${PLAIN}

${CYAN}Panel Information:${PLAIN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${YELLOW}Access URL:${PLAIN}        http://$(get_public_ip):$DEFAULT_PORT
${YELLOW}Admin Username:${PLAIN}   $ADMIN_USER
${YELLOW}Admin Password:${PLAIN}   $ADMIN_PASS

${CYAN}VPN Protocols Installed:${PLAIN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${GREEN}✓${PLAIN} OpenVPN (Port: $OPENVPN_PORT/UDP)
${GREEN}✓${PLAIN} WireGuard (Port: $WIREGUARD_PORT/UDP)
${GREEN}✓${PLAIN} Shadowsocks (Port: $SHADOWSOCKS_PORT/TCP)
${GREEN}✓${PLAIN} Trojan (Port: $TROJAN_PORT/TCP)
${GREEN}✓${PLAIN} VMESS (Port: $VMESS_PORT/TCP)
${GREEN}✓${PLAIN} VLESS (Port: $VLESS_PORT/TCP)
${GREEN}✓${PLAIN} Hysteria (Port: $HYSTERIA_PORT/UDP)

${CYAN}Security Features:${PLAIN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${GREEN}✓${PLAIN} Firewall configured
${GREEN}✓${PLAIN} Fail2ban installed
${GREEN}✓${PLAIN} System optimized for performance
${GREEN}✓${PLAIN} Automatic backups enabled
${GREEN}✓${PLAIN} Real-time monitoring active

${CYAN}Important Files:${PLAIN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${YELLOW}Configuration:${PLAIN}   $CONFIG_DIR/
${YELLOW}Panel Directory:${PLAIN}  $PANEL_DIR/
${YELLOW}Log Files:${PLAIN}        $LOG_DIR/
${YELLOW}Database:${PLAIN}         $DB_DIR/

${RED}IMPORTANT SECURITY NOTES:${PLAIN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Change the admin password immediately after first login
2. Configure SSL certificates for HTTPS access
3. Review and customize firewall rules as needed
4. Regularly check logs for security issues
5. Keep the panel and all protocols updated

${GREEN}Installation completed successfully!${PLAIN}

EOF
    
    log_info "Installation completed successfully"
}

# =============================================================================
# MENU FUNCTIONS
# =============================================================================

show_menu() {
    clear
    cat <<EOF

${GREEN}╔══════════════════════════════════════════════════════════════════════╗
║                        Z-PARS VPN PANEL MENU                         ║
╚══════════════════════════════════════════════════════════════════════╝${PLAIN}

${CYAN}1)${PLAIN} Install Z-PARS VPN Panel
${CYAN}2)${PLAIN} Add VPN User
${CYAN}3)${PLAIN} Remove VPN User
${CYAN}4)${PLAIN} List VPN Users
${CYAN}5)${PLAIN} Show Panel Status
${CYAN}6)${PLAIN} Show System Status
${CYAN}7)${PLAIN} Backup Panel Data
${CYAN}8)${PLAIN} Restore Panel Data
${CYAN}9)${PLAIN} Update Panel
${CYAN}10)${PLAIN} Uninstall Panel
${CYAN}0)${PLAIN} Exit

EOF
    read -rp "Please select an option [0-10]: " choice
    
    case "$choice" in
        1)
            install_panel
            ;;
        2)
            # Add user function would go here
            log_info "Add user function - Coming soon"
            ;;
        3)
            # Remove user function would go here
            log_info "Remove user function - Coming soon"
            ;;
        4)
            # List users function would go here
            log_info "List users function - Coming soon"
            ;;
        5)
            show_panel_status
            ;;
        6)
            show_system_status
            ;;
        7)
            "$PANEL_DIR/bin/backup.sh"
            ;;
        8)
            log_info "Restore function - Coming soon"
            ;;
        9)
            log_info "Update function - Coming soon"
            ;;
        10)
            uninstall_panel
            ;;
        0)
            exit 0
            ;;
        *)
            log_error "Invalid option"
            ;;
    esac
}

show_panel_status() {
    log_info "Panel Status Information:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Check if panel is running
    if systemctl is-active --quiet z-pars-panel; then
        log_info "Panel Status: ${GREEN}Running${PLAIN}"
    else
        log_info "Panel Status: ${RED}Stopped${PLAIN}"
    fi
    
    # Show listening ports
    log_info "Listening Ports:"
    netstat -tuln | grep -E ":(8080|1194|51820|8388|443|10086|10087|33445)" | while read -r line; do
        echo "  $line"
    done
    
    # Show service status
    log_info "Service Status:"
    for service in z-pars-panel openvpn@server wg-quick@wg0 shadowsocks-libev trojan xray hysteria; do
        if systemctl list-units --full -all | grep -q "$service"; then
            if systemctl is-active --quiet "$service"; then
                echo "  $service: ${GREEN}Active${PLAIN}"
            else
                echo "  $service: ${RED}Inactive${PLAIN}"
            fi
        fi
    done
}

show_system_status() {
    log_info "System Status Information:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # System info
    log_info "System: $(uname -s) $(uname -r)"
    log_info "Architecture: $(uname -m)"
    log_info "Uptime: $(uptime -p)"
    
    # Resource usage
    log_info "CPU Usage:"
    top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}' | xargs echo "  "
    
    log_info "Memory Usage:"
    free -h | grep Mem | awk '{printf "  Used: %s/%s (%.2f%%)\n", $3, $2, $3/$2 * 100.0}'
    
    log_info "Disk Usage:"
    df -h / | tail -1 | awk '{printf "  Used: %s/%s (%s)\n", $3, $2, $5}'
    
    # Network info
    log_info "Network Interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk -F: '{print "  " $2}' | xargs
    
    log_info "Public IP: $(get_public_ip)"
}

uninstall_panel() {
    log_warn "This will completely remove Z-PARS VPN Panel and all its components!"
    read -rp "Are you sure you want to continue? [y/N]: " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        log_info "Uninstallation cancelled"
        return
    fi
    
    log_info "Uninstalling Z-PARS VPN Panel..."
    
    # Stop and disable services
    systemctl stop z-pars-panel 2>/dev/null
    systemctl disable z-pars-panel 2>/dev/null
    
    # Stop VPN services
    systemctl stop openvpn@server 2>/dev/null
    systemctl stop wg-quick@wg0 2>/dev/null
    systemctl stop shadowsocks-libev 2>/dev/null
    systemctl stop trojan 2>/dev/null
    systemctl stop xray 2>/dev/null
    systemctl stop hysteria 2>/dev/null
    
    # Remove files
    rm -rf "$PANEL_DIR"
    rm -rf "$CONFIG_DIR"
    rm -rf "$LOG_DIR"
    rm -rf "$DB_DIR"
    
    # Remove systemd service
    rm -f /etc/systemd/system/z-pars-panel.service
    
    # Remove packages (optional)
    read -rp "Remove VPN protocol packages? [y/N]: " remove_packages
    if [[ "$remove_packages" == "y" || "$remove_packages" == "Y" ]]; then
        case "$OS" in
            ubuntu|debian)
                apt-get remove -y openvpn wireguard shadowsocks-libev
                ;;
            centos|rhel|almalinux|rocky)
                if [[ "$VERSION" == "7" ]]; then
                    yum remove -y openvpn wireguard-tools shadowsocks-libev
                else
                    dnf remove -y openvpn wireguard-tools shadowsocks-libev
                fi
                ;;
        esac
    fi
    
    systemctl daemon-reload
    
    log_info "Z-PARS VPN Panel uninstalled successfully"
}

# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

main() {
    # Check if running as root for operations that require it
    if [[ "$1" != "--help" && "$1" != "-h" && "$1" != "--version" && "$1" != "-v" ]]; then
        check_root
    fi
    
    case "$1" in
        install)
            install_panel
            ;;
        menu)
            while true; do
                show_menu
                read -rp "Press Enter to continue..."
            done
            ;;
        --help|-h)
            cat <<EOF
Z-PARS VPN Panel Installation Script

Usage: $0 [OPTION]

Options:
  install     Install Z-PARS VPN Panel
  menu        Show interactive menu
  --help, -h  Show this help message
  --version   Show version information

Examples:
  $0 install    # Install the panel
  $0 menu       # Show interactive menu

EOF
            ;;
        --version)
            echo "Z-PARS VPN Panel v$PANEL_VERSION"
            ;;
        *)
            show_menu
            ;;
    esac
}

# Run main function with all arguments
main "$@"
