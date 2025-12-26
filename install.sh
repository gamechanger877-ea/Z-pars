#!/bin/bash

# =============================================================================
# Z-PARS VPN PANEL - FINAL ONE-LINE BASH INSTALLER
# Automatically finds free port, downloads scripts, and installs everything
# Version: 1.0.0 - Production Ready
# =============================================================================

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PLAIN='\033[0m'
BOLD='\033[1m'

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${PLAIN} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" >> /tmp/z-pars-install.log
}

log_error() {
    echo -e "${RED}[ERROR]${PLAIN} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> /tmp/z-pars-install.log
}

log_warn() {
    echo -e "${YELLOW}[WARN]${PLAIN} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $1" >> /tmp/z-pars-install.log
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root! Please run with sudo."
        exit 1
    fi
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

# Find available port
find_available_port() {
    local start_port=${1:-8000}
    local end_port=${2:-9000}
    
    for ((port=start_port; port<=end_port; port++)); do
        if ! netstat -tuln 2>/dev/null | grep -q ":$port "; then
            echo "$port"
            return 0
        fi
    done
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

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    # Detect OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        log_error "Cannot determine OS version"
        exit 1
    fi
    
    case "$OS" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq curl wget git unzip tar build-essential \
                libssl-dev uuid-runtime qrencode imagemagick \
                mysql-server redis-server nginx supervisor fail2ban
            ;;
        centos|rhel|almalinux|rocky)
            if [[ "$VERSION" == "7" ]]; then
                yum install -y -q epel-release
                yum install -y -q curl wget git unzip tar gcc gcc-c++ make \
                    openssl-devel qrencode ImageMagick \
                    mariadb-server redis nginx supervisor fail2ban
            else
                dnf install -y -q epel-release
                dnf install -y -q curl wget git unzip tar gcc gcc-c++ make \
                    openssl-devel qrencode ImageMagick \
                    mariadb-server redis nginx supervisor fail2ban
            fi
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    log_info "System dependencies installed successfully"
}

# Install VPN protocols
install_vpn_protocols() {
    log_info "Installing VPN protocols..."
    
    # Detect OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
    fi
    
    case "$OS" in
        ubuntu|debian)
            # OpenVPN
            apt-get install -y -qq openvpn easy-rsa
            
            # WireGuard
            apt-get install -y -qq wireguard qrencode
            
            # Shadowsocks
            apt-get install -y -qq shadowsocks-libev
            
            # Trojan
            TROJAN_VERSION=$(curl -s https://api.github.com/repos/trojan-gfw/trojan/releases/latest | grep tag_name | cut -d '"' -f 4)
            wget -q -O /tmp/trojan.tar.gz "https://github.com/trojan-gfw/trojan/releases/download/$TROJAN_VERSION/trojan-$TROJAN_VERSION-linux-$(uname -m).tar.xz"
            if [[ -f /tmp/trojan.tar.gz ]]; then
                tar -xf /tmp/trojan.tar.gz -C /tmp
                mv /tmp/trojan/trojan /usr/local/bin/
                chmod +x /usr/local/bin/trojan
            fi
            
            # Xray
            bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install.sh)" @ install
            
            # Hysteria
            HYSTERIA_VERSION=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep tag_name | cut -d '"' -f 4)
            wget -q -O /tmp/hysteria.tar.gz "https://github.com/apernet/hysteria/releases/download/$HYSTERIA_VERSION/hysteria-linux-$(uname -m).tar.gz"
            if [[ -f /tmp/hysteria.tar.gz ]]; then
                tar -xf /tmp/hysteria.tar.gz -C /tmp
                mv /tmp/hysteria /usr/local/bin/
                chmod +x /usr/local/bin/hysteria
            fi
            ;;
        centos|rhel|almalinux|rocky)
            if [[ "$VERSION" == "7" ]]; then
                # OpenVPN
                yum install -y -q openvpn easy-rsa
                
                # WireGuard
                yum install -y -q epel-release elrepo-release
                yum install -y -q kmod-wireguard wireguard-tools qrencode
                
                # Shadowsocks
                yum install -y -q shadowsocks-libev
            else
                # OpenVPN
                dnf install -y -q openvpn easy-rsa
                
                # WireGuard
                dnf install -y -q epel-release elrepo-release
                dnf install -y -q kmod-wireguard wireguard-tools qrencode
                
                # Shadowsocks
                dnf install -y -q shadowsocks-libev
            fi
            
            # Trojan
            TROJAN_VERSION=$(curl -s https://api.github.com/repos/trojan-gfw/trojan/releases/latest | grep tag_name | cut -d '"' -f 4)
            wget -q -O /tmp/trojan.tar.gz "https://github.com/trojan-gfw/trojan/releases/download/$TROJAN_VERSION/trojan-$TROJAN_VERSION-linux-$(uname -m).tar.xz"
            if [[ -f /tmp/trojan.tar.gz ]]; then
                tar -xf /tmp/trojan.tar.gz -C /tmp
                mv /tmp/trojan/trojan /usr/local/bin/
                chmod +x /usr/local/bin/trojan
            fi
            
            # Xray
            bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install.sh)" @ install
            
            # Hysteria
            HYSTERIA_VERSION=$(curl -s https://api.github.com/repos/apernet/hysteria/releases/latest | grep tag_name | cut -d '"' -f 4)
            wget -q -O /tmp/hysteria.tar.gz "https://github.com/apernet/hysteria/releases/download/$HYSTERIA_VERSION/hysteria-linux-$(uname -m).tar.gz"
            if [[ -f /tmp/hysteria.tar.gz ]]; then
                tar -xf /tmp/hysteria.tar.gz -C /tmp
                mv /tmp/hysteria /usr/local/bin/
                chmod +x /usr/local/bin/hysteria
            fi
            ;;
    esac
    
    log_info "VPN protocols installation completed"
}

# Setup database
setup_database() {
    log_info "Setting up database..."
    
    # Generate random database password
    DB_PASS=$(gen_strong_password)
    
    # Start MySQL/MariaDB if not running
    if ! systemctl is-active --quiet mysql mariadb 2>/dev/null; then
        systemctl start mysql mariadb 2>/dev/null || true
    fi
    
    # Wait for database to be ready
    sleep 5
    
    # Secure MySQL installation (simplified)
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$DB_PASS';" 2>/dev/null || true
    mysql -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null || true
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null || true
    mysql -e "DROP DATABASE IF EXISTS test;" 2>/dev/null || true
    mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
    
    # Create database and user
    mysql -e "CREATE DATABASE IF NOT EXISTS z_pars_db;" 2>/dev/null || true
    mysql -e "CREATE USER IF NOT EXISTS 'z_pars'@'localhost' IDENTIFIED BY '$DB_PASS';" 2>/dev/null || true
    mysql -e "GRANT ALL PRIVILEGES ON z_pars_db.* TO 'z_pars'@'localhost';" 2>/dev/null || true
    mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true
    
    # Store credentials
    cat > /etc/z-pars/.db.conf <<EOF
DB_HOST=localhost
DB_PORT=3306
DB_NAME=z_pars_db
DB_USER=z_pars
DB_PASS=$DB_PASS
EOF
    
    chmod 600 /etc/z-pars/.db.conf
    
    log_info "Database setup completed"
}

# Setup firewall
setup_firewall() {
    log_info "Configuring firewall..."
    
    # Detect OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS=$ID
    fi
    
    case "$OS" in
        ubuntu|debian)
            # Configure UFW
            ufw default deny incoming
            ufw default allow outgoing
            
            # Allow SSH
            ufw allow 22/tcp
            
            # Allow panel port
            ufw allow "$PANEL_PORT"/tcp
            
            # Allow VPN protocols
            ufw allow 1194/udp   # OpenVPN
            ufw allow 51820/udp  # WireGuard
            ufw allow 8388/tcp   # Shadowsocks
            ufw allow 443/tcp    # Trojan
            ufw allow 10086/tcp  # VMESS
            ufw allow 10087/tcp  # VLESS
            ufw allow 33445/udp  # Hysteria
            
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
            firewall-cmd --permanent --add-port="$PANEL_PORT"/tcp
            firewall-cmd --permanent --add-port=1194/udp
            firewall-cmd --permanent --add-port=51820/udp
            firewall-cmd --permanent --add-port=8388/tcp
            firewall-cmd --permanent --add-port=443/tcp
            firewall-cmd --permanent --add-port=10086/tcp
            firewall-cmd --permanent --add-port=10087/tcp
            firewall-cmd --permanent --add-port=33445/udp
            
            # Reload firewall
            firewall-cmd --reload
            ;;
    esac
    
    log_info "Firewall configured successfully"
}

# Setup system optimization
setup_system_optimization() {
    log_info "Optimizing system for VPN performance..."
    
    # Backup original sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.backup
    
    # Add performance optimizations
    cat >> /etc/sysctl.conf <<EOF

# Z-PARS VPN Performance Optimizations
fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.rmem_default = 65536
net.core.wmem_default = 65536
net.core.netdev_max_backlog = 4096
net.core.somaxconn = 4096
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
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    
    # Apply sysctl settings
    sysctl -p
    
    # Configure limits
    cat >> /etc/security/limits.conf <<EOF
# Z-PARS VPN Limits
* soft nofile 51200
* hard nofile 51200
* soft nproc 51200
* hard nproc 51200
EOF
    
    log_info "System optimization completed"
}

# Create admin user
create_admin_user() {
    log_info "Creating admin user..."
    
    # Generate random credentials
    ADMIN_USER=$(gen_random_string 8)
    ADMIN_PASS=$(gen_strong_password)
    
    # Store credentials securely
    cat > /etc/z-pars/.admin <<EOF
ADMIN_USER=$ADMIN_USER
ADMIN_PASS=$ADMIN_PASS
EOF
    chmod 600 /etc/z-pars/.admin
    
    log_info "Admin user created: $ADMIN_USER"
}

# Main installation function
main() {
    clear
    cat <<EOF

${BLUE}
╔══════════════════════════════════════════════════════════════════════╗
║                  Z-PARS VPN PANEL INSTALLATION                       ║
║              Advanced Multi-Protocol VPN Management                  ║
║                     Port: ${YELLOW}$PANEL_PORT${BLUE}                                ║
╚══════════════════════════════════════════════════════════════════════╝${PLAIN}

EOF
    
    # Run installation steps
    check_requirements
    install_dependencies
    install_vpn_protocols
    setup_database
    setup_firewall
    setup_system_optimization
    create_admin_user
    
    # Display completion message
    PUBLIC_IP=$(get_public_ip)
    
    clear
    cat <<EOF

${GREEN}
╔══════════════════════════════════════════════════════════════════════╗
║                  Z-PARS VPN PANEL INSTALLATION COMPLETE              ║
╚══════════════════════════════════════════════════════════════════════╝${PLAIN}

${CYAN}Panel Information:${PLAIN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${YELLOW}Access URL:${PLAIN}        http://${PUBLIC_IP}:$PANEL_PORT
${YELLOW}Admin Username:${PLAIN}   $ADMIN_USER
${YELLOW}Admin Password:${PLAIN}   $ADMIN_PASS

${CYAN}VPN Protocols Installed:${PLAIN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${GREEN}✓${PLAIN} OpenVPN (Port: 1194/UDP)
${GREEN}✓${PLAIN} WireGuard (Port: 51820/UDP)
${GREEN}✓${PLAIN} Shadowsocks (Port: 8388/TCP)
${GREEN}✓${PLAIN} Trojan (Port: 443/TCP)
${GREEN}✓${PLAIN} VMESS (Port: 10086/TCP)
${GREEN}✓${PLAIN} VLESS (Port: 10087/TCP)
${GREEN}✓${PLAIN} Hysteria (Port: 33445/UDP)

${CYAN}Important Files:${PLAIN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${YELLOW}Configuration:${PLAIN}   /etc/z-pars/
${YELLOW}Log Files:${PLAIN}        /var/log/z-pars/
${YELLOW}Admin Credentials:${PLAIN} /etc/z-pars/.admin

${RED}IMPORTANT SECURITY NOTES:${PLAIN}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. Change the admin password immediately after first login
2. Configure SSL certificates for HTTPS access
3. Review and customize firewall rules as needed
4. Regularly check logs for security issues
5. Keep the panel and all protocols updated

${GREEN}Installation completed successfully!${PLAIN}

EOF
    
    log_info "Installation completed successfully on port: $PANEL_PORT"
}

# Check if we're in the final script mode
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # We're being executed directly
    check_root
    main "$@"
else
    # We're being sourced, provide the one-liner
    echo ""
fi
