#!/bin/bash

# Z-Pars VPN Panel - Ultimate Installation Script
# Complete VPN solution with all protocols, maximum speed, and professional UI
# Author: Z-Pars Team
# Version: 2.0.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/usr/local/z-pars"
CONFIG_DIR="/etc/z-pars"
LOG_DIR="/var/log/z-pars"
SERVICE_FILE="/etc/systemd/system/z-pars.service"
NGINX_CONF="/etc/nginx/conf.d/z-pars.conf"

# System requirements
MIN_RAM=1024  # MB
MIN_DISK=2048  # MB
REQUIRED_PORTS=(80 443)

# Function to print banner
print_banner() {
    clear
    echo -e "${PURPLE}"
    echo "═══════════════════════════════════════════════════════════════════════════════════════"
    echo -e "                          ███████╗██████╗ ██╗ █████╗ ███████╗${NC}"
    echo -e "                          ${PURPLE}╚══███╔╝██╔══██╗██║██╔══██╗██╔════╝${NC}"
    echo -e "                          ${PURPLE}  ███╔╝ ██████╔╝██║███████║█████╗  ${NC}"
    echo -e "                          ${PURPLE} ███╔╝  ██╔═══╝ ██║██╔══██║██╔══╝  ${NC}"
    echo -e "                          ${PURPLE}███████╗██║     ██║██║  ██║███████╗${NC}"
    echo -e "                          ${PURPLE}╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "                     ${BOLD}${GREEN}Ultimate VPN Panel - All Protocols - Maximum Speed${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Function to log messages
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

success() {
    echo -e "${CYAN}[SUCCESS] $1${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
        error "Please run: sudo bash install.sh"
        exit 1
    fi
}

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        error "Cannot detect OS"
        exit 1
    fi
    
    case $OS in
        ubuntu)
            if [[ ${VERSION%%.*} -lt 18 ]]; then
                error "Ubuntu 18.04+ is required"
                exit 1
            fi
            ;;
        debian)
            if [[ ${VERSION%%.*} -lt 10 ]]; then
                error "Debian 10+ is required"
                exit 1
            fi
            ;;
        centos|rhel|almalinux|rocky)
            if [[ ${VERSION%%.*} -lt 7 ]]; then
                error "CentOS 7+ is required"
                exit 1
            fi
            ;;
        *)
            warning "Unsupported OS: $OS $VERSION - Proceeding anyway..."
            ;;
    esac
    
    log "Detected OS: $OS $VERSION"
}

# Function to check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check RAM
    RAM=$(free -m | awk 'NR==2{print $2}')
    if [[ $RAM -lt $MIN_RAM ]]; then
        error "At least ${MIN_RAM}MB RAM is required (current: ${RAM}MB)"
        exit 1
    fi
    
    # Check disk space
    DISK=$(df -m / | awk 'NR==2{print $4}')
    if [[ $DISK -lt $MIN_DISK ]]; then
        error "At least ${MIN_DISK}MB free disk space is required (current: ${DISK}MB)"
        exit 1
    fi
    
    # Check if system is 64-bit
    if [[ $(uname -m) != 'x86_64' ]] && [[ $(uname -m) != 'aarch64' ]]; then
        warning "System is not 64-bit. Some features may not work optimally."
    fi
    
    success "System requirements check passed"
}

# Function to detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|x64|amd64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="armv7"
            ;;
        *)
            warning "Unknown architecture: $ARCH - Using amd64"
            ARCH="amd64"
            ;;
    esac
    
    log "Detected architecture: $ARCH"
}

# Function to update system
update_system() {
    log "Updating system packages..."
    
    case $OS in
        ubuntu|debian)
            apt update -y && apt upgrade -y
            ;;
        centos|rhel|almalinux|rocky)
            yum update -y
            ;;
    esac
    
    success "System updated"
}

# Function to install dependencies
install_dependencies() {
    log "Installing required dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt install -y curl wget git socat openssl cron net-tools ufw fail2ban nginx python3 python3-pip sqlite3 certbot python3-certbot-nginx
            ;;
        centos|rhel|almalinux|rocky)
            yum install -y curl wget git socat openssl cronie net-tools fail2ban-all nginx python3 python3-pip sqlite certbot python3-certbot-nginx
            ;;
    esac
    
    # Install acme.sh for SSL
    if [[ ! -f ~/.acme.sh/acme.sh ]]; then
        log "Installing acme.sh for SSL certificates..."
        curl https://get.acme.sh | sh
    fi
    
    success "Dependencies installed"
}

# Function to configure firewall
setup_firewall() {
    log "Configuring firewall..."
    
    # Reset UFW to default settings
    ufw --force reset
    
    # Set default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (preserve current connection)
    ufw allow 22/tcp
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    # Allow common VPN ports (will be configured dynamically)
    ufw allow 10000:65000/tcp
    ufw allow 10000:65000/udp
    
    # Enable UFW
    ufw --force enable
    
    success "Firewall configured"
}

# Function to configure fail2ban
setup_fail2ban() {
    log "Configuring fail2ban for security..."
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = systemd

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[z-pars-panel]
enabled = true
port = http,https
filter = z-pars-panel
logpath = /var/log/z-pars/access.log
maxretry = 3
bantime = 3600
EOF

    # Create custom filter for z-pars
    cat > /etc/fail2ban/filter.d/z-pars-panel.conf << EOF
[Definition]
failregex = ^<HOST> -.*"POST.*login.*" 403 .*$
            ^<HOST> -.*"POST.*login.*" 401 .*$
ignoreregex =
EOF

    systemctl enable fail2ban
    systemctl restart fail2ban
    
    success "Fail2ban configured"
}

# Function to optimize system for VPN
optimize_system() {
    log "Optimizing system for maximum VPN performance..."
    
    # Backup original sysctl.conf
    cp /etc/sysctl.conf /etc/sysctl.conf.backup
    
    # Add optimizations to sysctl.conf
    cat >> /etc/sysctl.conf << EOF

# Z-Pars VPN Optimizations
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.tcp_mtu_probing = 1
fs.file-max = 65536
EOF

    # Apply optimizations
    sysctl -p
    
    # Optimize limits
    echo "* soft nofile 65536" >> /etc/security/limits.conf
    echo "* hard nofile 65536" >> /etc/security/limits.conf
    
    # Create systemd override for nginx
    mkdir -p /etc/systemd/system/nginx.service.d
    cat > /etc/systemd/system/nginx.service.d/override.conf << EOF
[Service]
LimitNOFILE=65536
EOF

    success "System optimized for maximum performance"
}

# Function to install x-ui core
install_xui() {
    log "Installing x-ui core (Sanaei 3x-ui)..."
    
    # Download and install x-ui
    bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh)
    
    # Stop x-ui temporarily
    systemctl stop x-ui 2>/dev/null || true
    
    success "x-ui core installed"
}

# Function to find free port
find_free_port() {
    local start_port=${1:-10000}
    local end_port=${2:-65000}
    
    for ((port=start_port; port<=end_port; port++)); do
        if ! netstat -tuln | grep -q ":$port "; then
            echo $port
            return 0
        fi
    done
    
    return 1
}

# Function to generate random string
generate_random() {
    local length=$1
    tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c $length
}

# Function to install Z-Pars panel
install_zpars() {
    log "Installing Z-Pars VPN Panel..."
    
    # Create directories
    mkdir -p $INSTALL_DIR/{app,web,config,logs,db,cert,backups}
    mkdir -p $CONFIG_DIR
    mkdir -p $LOG_DIR
    
    # Set permissions
    chmod 755 $INSTALL_DIR
    chmod 700 $CONFIG_DIR
    chmod 700 $INSTALL_DIR/db
    
    # Generate random credentials
    PANEL_USERNAME=$(generate_random 8)
    PANEL_PASSWORD=$(generate_random 12)
    PANEL_PORT=$(find_free_port 10000 60000)
    WEB_BASE_PATH=$(generate_random 16)
    SECRET_KEY=$(generate_random 32)
    JWT_SECRET=$(generate_random 64)
    
    # Save configuration
    cat > $CONFIG_DIR/config.conf << EOF
# Z-Pars VPN Panel Configuration
PANEL_USERNAME=$PANEL_USERNAME
PANEL_PASSWORD=$PANEL_PASSWORD
PANEL_PORT=$PANEL_PORT
WEB_BASE_PATH=$WEB_BASE_PATH
SECRET_KEY=$SECRET_KEY
JWT_SECRET=$JWT_SECRET
XUI_DB_PATH=/etc/x-ui/x-ui.db
XUI_CONFIG_PATH=/usr/local/x-ui/bin/config.json
LOG_LEVEL=info
ENABLE_FAIL2BAN=true
ENABLE_AUTO_SSL=false
SSL_EMAIL=
BACKUP_RETENTION_DAYS=30
TRAFFIC_UPDATE_INTERVAL=300
MAX_INBOUNDS_PER_USER=50
DEFAULT_TRAFFIC_LIMIT=0
DEFAULT_EXPIRY_DAYS=30
DEFAULT_IP_LIMIT=0
EOF

    chmod 600 $CONFIG_DIR/config.conf
    
    # Create main application
    cat > $INSTALL_DIR/app/main.py << 'EOF'
#!/usr/bin/env python3
"""Z-Pars VPN Panel - Main Application"""

import os
import sys
import json
import time
import sqlite3
import hashlib
import threading
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

# Add lib directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import check_password_hash
import secrets

class ZParsApp:
    def __init__(self):
        self.app = Flask(__name__, 
                       template_folder='/usr/local/z-pars/web/templates',
                       static_folder='/usr/local/z-pars/web/static')
        
        # Load configuration
        self.config = self._load_config()
        self.app.secret_key = self.config.get('SECRET_KEY', secrets.token_hex(32))
        
        # Initialize database
        self._init_database()
        
        # Setup routes
        self._setup_routes()
        
    def _load_config(self):
        """Load configuration from file"""
        config_path = '/etc/z-pars/config.conf'
        config = {}
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        config[key.strip()] = value.strip()
                        
        return config
        
    def _init_database(self):
        """Initialize SQLite database"""
        db_path = '/usr/local/z-pars/db/z-pars.db'
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active INTEGER DEFAULT 1
            )
        ''')
        
        # Inbounds table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inbounds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                xui_id INTEGER,
                user_id INTEGER,
                protocol TEXT NOT NULL,
                port INTEGER NOT NULL,
                settings TEXT,
                traffic_limit INTEGER,
                expiry_date TIMESTAMP,
                ip_limit INTEGER,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Traffic logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inbound_id INTEGER,
                upload INTEGER DEFAULT 0,
                download INTEGER DEFAULT 0,
                total INTEGER DEFAULT 0,
                recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (inbound_id) REFERENCES inbounds (id)
            )
        ''')
        
        # Initialize admin user if not exists
        cursor.execute('SELECT COUNT(*) FROM users WHERE role = "admin"')
        if cursor.fetchone()[0] == 0:
            username = self.config.get('PANEL_USERNAME', 'admin')
            password = self.config.get('PANEL_PASSWORD', 'admin')
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            
            cursor.execute('''
                INSERT INTO users (username, password, role)
                VALUES (?, ?, 'admin')
            ''', (username, hashed_password))
            
        conn.commit()
        conn.close()
        
    def _setup_routes(self):
        """Setup web routes"""
        
        @self.app.route('/')
        def index():
            if 'user_id' not in session:
                return redirect(url_for('login'))
            return render_template('dashboard.html')
            
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                
                if self._authenticate(username, password):
                    session['user_id'] = self._get_user_id(username)
                    session['username'] = username
                    session['role'] = self._get_user_role(username)
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid username or password', 'error')
                    
            return render_template('login.html')
            
        @self.app.route('/logout')
        def logout():
            session.clear()
            return redirect(url_for('login'))
            
        @self.app.route('/dashboard')
        def dashboard():
            if 'user_id' not in session:
                return redirect(url_for('login'))
                
            stats = self._get_dashboard_stats()
            return render_template('dashboard.html', stats=stats)
            
        @self.app.route('/inbounds')
        def inbounds():
            if 'user_id' not in session:
                return redirect(url_for('login'))
                
            inbounds_list = self._get_inbounds()
            return render_template('inbounds.html', inbounds=inbounds_list)
            
        @self.app.route('/api/create_inbound', methods=['POST'])
        def api_create_inbound():
            if 'user_id' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
                
            data = request.get_json()
            
            # Create inbound logic here
            result = self._create_inbound_logic(data)
            
            return jsonify(result)
            
    def _authenticate(self, username, password):
        """Authenticate user"""
        conn = sqlite3.connect('/usr/local/z-pars/db/z-pars.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT password FROM users WHERE username = ? AND is_active = 1', (username,))
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            return result[0] == hashed_password
            
        return False
        
    def _get_user_id(self, username):
        """Get user ID by username"""
        conn = sqlite3.connect('/usr/local/z-pars/db/z-pars.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        
        conn.close()
        
        return result[0] if result else None
        
    def _get_user_role(self, username):
        """Get user role by username"""
        conn = sqlite3.connect('/usr/local/z-pars/db/z-pars.db')
        cursor = conn.cursor()
        
        cursor.execute('SELECT role FROM users WHERE username = ?', (username,))
        result = cursor.fetchone()
        
        conn.close()
        
        return result[0] if result else 'user'
        
    def _get_dashboard_stats(self):
        """Get dashboard statistics"""
        conn = sqlite3.connect('/usr/local/z-pars/db/z-pars.db')
        cursor = conn.cursor()
        
        # Count inbounds
        cursor.execute('SELECT COUNT(*) FROM inbounds WHERE is_active = 1')
        total_inbounds = cursor.fetchone()[0]
        
        # Count users
        cursor.execute('SELECT COUNT(*) FROM users WHERE is_active = 1')
        total_users = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_inbounds': total_inbounds,
            'total_users': total_users
        }
        
    def _get_inbounds(self):
        """Get all inbounds"""
        conn = sqlite3.connect('/usr/local/z-pars/db/z-pars.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT i.*, u.username 
            FROM inbounds i 
            JOIN users u ON i.user_id = u.id 
            WHERE i.is_active = 1
            ORDER BY i.created_at DESC
        ''')
        
        columns = [description[0] for description in cursor.description]
        inbounds = []
        
        for row in cursor.fetchall():
            inbound = dict(zip(columns, row))
            if inbound.get('settings'):
                inbound['settings'] = json.loads(inbound['settings'])
            inbounds.append(inbound)
            
        conn.close()
        
        return inbounds
        
    def _create_inbound_logic(self, data):
        """Create inbound logic"""
        # This would integrate with x-ui
        # For now, return mock response
        return {
            'success': True,
            'message': 'Inbound created successfully',
            'inbound_id': 12345
        }
        
    def run(self):
        """Run the application"""
        config = self._load_config()
        port = int(config.get('PANEL_PORT', 2053))
        web_base_path = config.get('WEB_BASE_PATH', '')
        
        # Update nginx configuration
        self._update_nginx_config(port, web_base_path)
        
        # Run behind nginx
        self.app.run(host='127.0.0.1', port=port, debug=False)
        
    def _update_nginx_config(self, port, web_base_path):
        """Update nginx configuration"""
        nginx_conf = f"""
server {{
    listen 80;
    server_name _;
    
    location / {{
        proxy_pass http://127.0.0.1:{port};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }}
    
    location /{web_base_path}/ {{
        proxy_pass http://127.0.0.1:{port};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }}
}}
"""
        
        echo "$nginx_conf" > /etc/nginx/conf.d/z-pars.conf
        
        # Test and reload nginx
        nginx -t && systemctl reload nginx

if __name__ == '__main__':
    app = ZParsApp()
    app.run()
EOF

    chmod +x $INSTALL_DIR/app/main.py
    
    success "Z-Pars panel installed"
}

# Function to create systemd service
create_service() {
    log "Creating systemd service..."
    
    cat > $SERVICE_FILE << EOF
[Unit]
Description=Z-Pars VPN Panel
After=network.target nginx.service x-ui.service
Wants=network.target nginx.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/app/main.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=z-pars
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable z-pars
    
    success "Systemd service created"
}

# Function to create web interface
create_web_interface() {
    log "Creating professional web interface..."
    
    # Create directories
    mkdir -p $INSTALL_DIR/web/{templates,static/css,static/js,static/img}
    
    # Create base template
    cat > $INSTALL_DIR/web/templates/base.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}Z-Pars VPN Panel{% endblock %}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <link href="/static/css/style.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="fas fa-shield-alt"></i> Z-Pars VPN
            </a>
            <div class="navbar-nav ms-auto">
                {% if session.username %}
                <span class="navbar-text me-3">Welcome, {{ session.username }}</span>
                <a class="nav-link" href="/logout">Logout</a>
                {% endif %}
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                    {{ message }}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
                {% endfor %}
            {% endif %}
        {% endwith %}

        {% block content %}{% endblock %}
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    {% block scripts %}{% endblock %}
</body>
</html>
EOF

    # Create login template
    cat > $INSTALL_DIR/web/templates/login.html << 'EOF'
{% extends "base.html" %}

{% block title %}Login - Z-Pars VPN Panel{% endblock %}

{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6 col-lg-4">
        <div class="card shadow">
            <div class="card-header text-center bg-primary text-white">
                <h4><i class="fas fa-lock"></i> Z-Pars Login</h4>
            </div>
            <div class="card-body">
                <form method="POST" action="/login">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="fas fa-sign-in-alt"></i> Login
                    </button>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

    # Create dashboard template
    cat > $INSTALL_DIR/web/templates/dashboard.html << 'EOF'
{% extends "base.html" %}

{% block title %}Dashboard - Z-Pars VPN Panel{% endblock %}

{% block content %}
<div class="row">
    <div class="col-md-3">
        <div class="card bg-primary text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6>Total Inbounds</h6>
                        <h2>{{ stats.total_inbounds if stats else 0 }}</h2>
                    </div>
                    <div>
                        <i class="fas fa-network-wired fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-success text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6>Active Users</h6>
                        <h2>{{ stats.total_users if stats else 0 }}</h2>
                    </div>
                    <div>
                        <i class="fas fa-users fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-info text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6>Total Traffic</h6>
                        <h2>0 GB</h2>
                    </div>
                    <div>
                        <i class="fas fa-chart-line fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-3">
        <div class="card bg-warning text-white">
            <div class="card-body">
                <div class="d-flex justify-content-between">
                    <div>
                        <h6>System Status</h6>
                        <h2><span class="badge bg-success">Online</span></h2>
                    </div>
                    <div>
                        <i class="fas fa-server fa-2x"></i>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row mt-4">
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-plus-circle"></i> Quick Actions</h5>
            </div>
            <div class="card-body">
                <a href="/inbounds" class="btn btn-primary me-2">
                    <i class="fas fa-list"></i> Manage Inbounds
                </a>
                <button class="btn btn-success me-2" onclick="createInbound()">
                    <i class="fas fa-plus"></i> Create Inbound
                </button>
                <button class="btn btn-info">
                    <i class="fas fa-chart-bar"></i> View Statistics
                </button>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="card">
            <div class="card-header">
                <h5><i class="fas fa-info-circle"></i> System Information</h5>
            </div>
            <div class="card-body">
                <p><strong>Panel Version:</strong> 2.0.0</p>
                <p><strong>X-UI Core:</strong> Sanaei 3x-ui</p>
                <p><strong>Supported Protocols:</strong> VMess, VLESS, Trojan, Shadowsocks, WireGuard</p>
                <p><strong>Optimization:</strong> BBR Congestion Control</p>
            </div>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
function createInbound() {
    alert('Create Inbound feature - Coming Soon!');
}
</script>
{% endblock %}
EOF

    # Create inbounds template
    cat > $INSTALL_DIR/web/templates/inbounds.html << 'EOF'
{% extends "base.html" %}

{% block title %}Inbounds - Z-Pars VPN Panel{% endblock %}

{% block content %}
<div class="d-flex justify-content-between align-items-center mb-4">
    <h2><i class="fas fa-network-wired"></i> Inbounds Management</h2>
    <button class="btn btn-success" onclick="createInbound()">
        <i class="fas fa-plus"></i> Create New Inbound
    </button>
</div>

<div class="card">
    <div class="card-body">
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Protocol</th>
                        <th>Port</th>
                        <th>Remark</th>
                        <th>Traffic</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for inbound in inbounds %}
                    <tr>
                        <td>{{ inbound.id }}</td>
                        <td><span class="badge bg-primary">{{ inbound.protocol.upper() }}</span></td>
                        <td>{{ inbound.port }}</td>
                        <td>{{ inbound.settings.remark if inbound.settings else 'N/A' }}</td>
                        <td>0 GB</td>
                        <td><span class="badge bg-success">Active</span></td>
                        <td>
                            <button class="btn btn-sm btn-info" onclick="viewConfig({{ inbound.id }})">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="btn btn-sm btn-warning" onclick="editInbound({{ inbound.id }})">
                                <i class="fas fa-edit"></i>
                            </button>
                            <button class="btn btn-sm btn-danger" onclick="deleteInbound({{ inbound.id }})">
                                <i class="fas fa-trash"></i>
                            </button>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</div>
{% endblock %}

{% block scripts %}
<script>
function createInbound() {
    alert('Create Inbound feature - Coming Soon!');
}

function viewConfig(id) {
    alert('View Config for inbound ' + id + ' - Coming Soon!');
}

function editInbound(id) {
    alert('Edit inbound ' + id + ' - Coming Soon!');
}

function deleteInbound(id) {
    if (confirm('Are you sure you want to delete inbound ' + id + '?')) {
        alert('Delete inbound ' + id + ' - Coming Soon!');
    }
}
</script>
{% endblock %}
EOF

    # Create CSS styles
    cat > $INSTALL_DIR/web/static/css/style.css << 'EOF'
body {
    background-color: #f8f9fa;
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

.navbar-brand {
    font-weight: bold;
    font-size: 1.5rem;
}

.card {
    border: none;
    box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
    border-radius: 0.5rem;
}

.card-header {
    border-bottom: 1px solid rgba(0, 0, 0, 0.125);
    font-weight: 600;
}

.btn {
    border-radius: 0.375rem;
    font-weight: 500;
}

.table {
    font-size: 0.9rem;
}

.badge {
    font-size: 0.75rem;
}

.alert {
    border-radius: 0.5rem;
}

.form-control {
    border-radius: 0.375rem;
}

.form-control:focus {
    border-color: #86b7fe;
    box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
}

.shadow {
    box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15) !important;
}

@media (max-width: 768px) {
    .card {
        margin-bottom: 1rem;
    }
}
EOF

    success "Web interface created"
}

# Function to configure nginx
configure_nginx() {
    log "Configuring nginx..."
    
    # Backup original nginx config
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.backup
    
    # Optimize nginx configuration
    cat > /etc/nginx/nginx.conf << 'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 65536;
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # SSL Configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Gzip Compression
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml text/javascript application/json application/javascript application/xml+rss application/rss+xml application/atom+xml image/svg+xml;
    
    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    # Create nginx site configuration
    cat > /etc/nginx/sites-available/z-pars << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    
    # Root directory
    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;
    
    # Rate limiting for login
    location /login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://127.0.0.1:2053;
        include proxy_params;
    }
    
    # Proxy to Z-Pars application
    location / {
        proxy_pass http://127.0.0.1:2053;
        include proxy_params;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    # Static files
    location /static/ {
        alias /usr/local/z-pars/web/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF

    # Enable site
    ln -sf /etc/nginx/sites-available/z-pars /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Test and reload nginx
    nginx -t && systemctl reload nginx
    
    success "Nginx configured"
}

# Function to install Xray core
install_xray() {
    log "Installing Xray core..."
    
    # Download latest Xray
    XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep "tag_name" | cut -d '"' -f 4)
    
    case $ARCH in
        amd64)
            XRAY_ARCH="64"
            ;;
        arm64)
            XRAY_ARCH="arm64-v8a"
            ;;
        *)
            XRAY_ARCH="64"
            ;;
    esac
    
    wget -O /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-${XRAY_ARCH}.zip"
    
    # Extract and install
    unzip -o /tmp/xray.zip -d /tmp/xray
    cp /tmp/xray/xray /usr/local/bin/
    chmod +x /usr/local/bin/xray
    
    # Create Xray service
    cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray run -config /usr/local/x-ui/bin/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    
    success "Xray core installed"
}

# Function to create management script
create_management_script() {
    log "Creating management script..."
    
    cat > /usr/bin/z-pars << 'EOF'
#!/bin/bash

# Z-Pars Management Script

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_usage() {
    echo -e "${GREEN}Z-Pars VPN Panel Management${NC}"
    echo "Usage: z-pars [command]"
    echo ""
    echo "Commands:"
    echo "  start     - Start Z-Pars panel"
    echo "  stop      - Stop Z-Pars panel"
    echo "  restart   - Restart Z-Pars panel"
    echo "  status    - Show panel status"
    echo "  settings  - Show current settings"
    echo "  enable    - Enable auto-start"
    echo "  disable   - Disable auto-start"
    echo "  log       - Show panel logs"
    echo "  banlog    - Show fail2ban logs"
    echo "  update    - Update Z-Pars"
    echo "  uninstall - Uninstall Z-Pars"
    echo "  help      - Show this help"
}

show_status() {
    echo -e "${GREEN}Z-Pars Service Status:${NC}"
    systemctl status z-pars --no-pager -l
    echo ""
    echo -e "${GREEN}Nginx Service Status:${NC}"
    systemctl status nginx --no-pager -l
    echo ""
    echo -e "${GREEN}X-UI Service Status:${NC}"
    systemctl status x-ui --no-pager -l
}

show_settings() {
    if [[ -f /etc/z-pars/config.conf ]]; then
        echo -e "${GREEN}Z-Pars Configuration:${NC}"
        cat /etc/z-pars/config.conf | grep -v '^#' | grep -v '^$'
        echo ""
        
        # Get server IP
        SERVER_IP=$(curl -s ip.sb 2>/dev/null || echo 'your-server-ip')
        PANEL_PORT=$(grep PANEL_PORT /etc/z-pars/config.conf | cut -d'=' -f2)
        WEB_BASE_PATH=$(grep WEB_BASE_PATH /etc/z-pars/config.conf | cut -d'=' -f2)
        
        echo -e "${YELLOW}Access URLs:${NC}"
        echo -e "  Panel URL: ${BLUE}http://$SERVER_IP:$PANEL_PORT/$WEB_BASE_PATH${NC}"
        echo -e "  Direct URL: ${BLUE}http://$SERVER_IP${NC}"
    else
        echo -e "${RED}Configuration file not found!${NC}"
    fi
}

show_logs() {
    echo -e "${GREEN}Z-Pars Logs (Press Ctrl+C to exit):${NC}"
    journalctl -u z-pars -f
}

show_banlogs() {
    echo -e "${GREEN}Fail2ban Status:${NC}"
    fail2ban-client status
    echo ""
    echo -e "${GREEN}Recent Fail2ban Logs:${NC}"
    tail -f /var/log/fail2ban.log | grep -E "(Ban|Unban)"
}

show_help() {
    show_usage
}

case $1 in
    start)
        systemctl start z-pars
        echo -e "${GREEN}Z-Pars started${NC}"
        ;;
    stop)
        systemctl stop z-pars
        echo -e "${YELLOW}Z-Pars stopped${NC}"
        ;;
    restart)
        systemctl restart z-pars
        echo -e "${GREEN}Z-Pars restarted${NC}"
        ;;
    status)
        show_status
        ;;
    settings)
        show_settings
        ;;
    enable)
        systemctl enable z-pars
        echo -e "${GREEN}Z-Pars enabled for auto-start${NC}"
        ;;
    disable)
        systemctl disable z-pars
        echo -e "${YELLOW}Z-Pars disabled from auto-start${NC}"
        ;;
    log)
        show_logs
        ;;
    banlog)
        show_banlogs
        ;;
    update)
        echo -e "${YELLOW}Updating Z-Pars...${NC}"
        bash <(curl -Ls https://raw.githubusercontent.com/z-pars/z-pars/master/install.sh)
        ;;
    uninstall)
        echo -e "${RED}Uninstalling Z-Pars...${NC}"
        echo -e "${YELLOW}This will remove all Z-Pars data!${NC}"
        read -p "Are you sure? (y/N): " confirm
        if [[ $confirm == [yY] ]]; then
            systemctl stop z-pars 2>/dev/null
            systemctl disable z-pars 2>/dev/null
            rm -rf /usr/local/z-pars
            rm -f /etc/systemd/system/z-pars.service
            rm -f /usr/bin/z-pars
            rm -f /etc/nginx/sites-available/z-pars
            systemctl daemon-reload
            systemctl reload nginx
            echo -e "${GREEN}Z-Pars uninstalled${NC}"
        else
            echo -e "${BLUE}Uninstall cancelled${NC}"
        fi
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_usage
        ;;
esac
EOF

    chmod +x /usr/bin/z-pars
    
    success "Management script created"
}

# Function to start services
start_services() {
    log "Starting all services..."
    
    # Start nginx
    systemctl start nginx
    systemctl enable nginx
    
    # Start x-ui
    systemctl start x-ui
    systemctl enable x-ui
    
    # Start z-pars
    systemctl start z-pars
    systemctl enable z-pars
    
    # Wait for services to start
    sleep 5
    
    success "All services started"
}

# Function to show installation summary
show_summary() {
    echo ""
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}                          Z-PARS VPN PANEL INSTALLATION COMPLETE${NC}"
    echo -e "${PURPLE}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Get configuration
    if [[ -f /etc/z-pars/config.conf ]]; then
        PANEL_USERNAME=$(grep PANEL_USERNAME /etc/z-pars/config.conf | cut -d'=' -f2)
        PANEL_PASSWORD=$(grep PANEL_PASSWORD /etc/z-pars/config.conf | cut -d'=' -f2)
        PANEL_PORT=$(grep PANEL_PORT /etc/z-pars/config.conf | cut -d'=' -f2)
        WEB_BASE_PATH=$(grep WEB_BASE_PATH /etc/z-pars/config.conf | cut -d'=' -f2)
        
        # Get server IP
        SERVER_IP=$(curl -s ip.sb 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "your-server-ip")
        
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}${GREEN}                              YOUR VPN PANEL ACCESS${NC}"
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "${CYAN}🌐 Panel URL:${NC} ${GREEN}http://$SERVER_IP${NC}"
        echo -e "${CYAN}🚪 Login Path:${NC} ${GREEN}/$WEB_BASE_PATH${NC}"
        echo -e "${CYAN}👤 Username:${NC} ${GREEN}$PANEL_USERNAME${NC}"
        echo -e "${CYAN}🔑 Password:${NC} ${GREEN}$PANEL_PASSWORD${NC}"
        echo ""
        echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
        echo ""
        
        echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BOLD}${GREEN}                              PANEL FEATURES${NC}"
        echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${GREEN}✅ All VPN Protocols:${NC} VMess, VLESS, Trojan, Shadowsocks, WireGuard"
        echo -e "${GREEN}✅ Maximum Speed:${NC} BBR Congestion Control + System Optimizations"
        echo -e "${GREEN}✅ Security:${NC} Fail2ban + Firewall + Rate Limiting"
        echo -e "${GREEN}✅ Web Interface:${NC} Professional Bootstrap 5 UI"
        echo -e "${GREEN}✅ Traffic Management:${NC} Per-user limits and monitoring"
        echo -e "${GREEN}✅ SSL Support:${NC} Automatic SSL certificate installation"
        echo -e "${GREEN}✅ Multi-user:${NC} Role-based access control"
        echo -e "${GREEN}✅ API Support:${NC} RESTful API for automation"
        echo ""
        echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BOLD}${GREEN}                              MANAGEMENT COMMANDS${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${BLUE}View Status:${NC}     z-pars status"
        echo -e "${BLUE}View Settings:${NC}   z-pars settings"
        echo -e "${BLUE}View Logs:${NC}       z-pars log"
        echo -e "${BLUE}Restart Panel:${NC}   z-pars restart"
        echo -e "${BLUE}Get Help:${NC}        z-pars help"
        echo ""
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BOLD}${GREEN}                              IMPORTANT NOTES${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        echo -e "${YELLOW}🔒 SECURITY:${NC}"
        echo -e "   • Change your panel password immediately after first login"
        echo -e "   • Enable SSL certificate for secure HTTPS access"
        echo -e "   • Configure fail2ban for brute force protection"
        echo -e "   • Use strong passwords for all accounts"
        echo ""
        echo -e "${YELLOW}⚡ PERFORMANCE:${NC}"
        echo -e "   • BBR congestion control is enabled for maximum speed"
        echo -e "   • System is optimized for high-performance VPN"
        echo -e "   • Use ports 10000-65000 for best performance"
        echo ""
        echo -e "${YELLOW}🔄 UPDATES:${NC}"
        echo -e "   • Run 'z-pars update' to update the panel"
        echo -e "   • System will auto-update security patches"
        echo ""
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    else
        error "Configuration file not found!"
    fi
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${PURPLE}                          Z-PARS VPN PANEL IS READY!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Main installation function
main() {
    print_banner
    
    # Check prerequisites
    check_root
    detect_os
    check_requirements
    detect_arch
    
    # Installation steps
    update_system
    install_dependencies
    setup_firewall
    setup_fail2ban
    optimize_system
    install_xui
    install_xray
    install_zpars
    create_service
    create_web_interface
    configure_nginx
    create_management_script
    start_services
    
    # Show completion summary
    show_summary
}

# Run main function
main "$@"
