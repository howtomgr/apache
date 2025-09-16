# Apache HTTP Server Installation Guide

Apache HTTP Server is a free and open-source cross-platform web server software developed and maintained by the Apache Software Foundation. Originally based on the NCSA HTTPd server, Apache has been the most popular web server on the Internet since April 1996, serving over 40% of active websites. It serves as a FOSS alternative to commercial web servers like Microsoft IIS, NGINX Plus, or F5 BIG-IP, offering enterprise-grade performance, security, and flexibility without licensing costs.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 1 core minimum (2+ cores recommended for production)
  - RAM: 512MB minimum (2GB+ recommended for production)
  - Storage: 500MB for installation (additional space for websites and logs)
  - Network: Stable connectivity for serving web requests
- **Operating System**: 
  - Linux: Any modern distribution with kernel 2.6.32+
  - macOS: 10.12+ (Sierra or newer)
  - Windows: Windows Server 2016+ or Windows 10
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 80 (HTTP)
  - Port 443 (HTTPS)
  - Additional ports for virtual hosts if needed
- **Dependencies**:
  - OpenSSL for SSL/TLS support
  - PCRE for regular expressions
  - APR (Apache Portable Runtime) libraries
  - Zlib for compression
- **System Access**: root or sudo privileges for installation


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install Apache (httpd) and utilities
sudo dnf install -y httpd httpd-tools mod_ssl mod_security

# RHEL/CentOS 7 (using yum)
sudo yum install -y epel-release
sudo yum install -y httpd httpd-tools mod_ssl mod_security

# Install additional modules
sudo dnf install -y httpd-devel httpd-manual

# Create necessary directories
sudo mkdir -p /etc/httpd/conf.d
sudo mkdir -p /var/log/httpd
sudo mkdir -p /var/www/html

# Set proper permissions
sudo chown -R apache:apache /var/www/html
sudo chown -R apache:apache /var/log/httpd

# Enable and start service
sudo systemctl enable --now httpd

# Verify installation
httpd -v
sudo systemctl status httpd
```

### Debian/Ubuntu

```bash
# Update package list
sudo apt update

# Install Apache and essential modules
sudo apt install -y apache2 apache2-utils apache2-dev libapache2-mod-security2

# Install additional tools
sudo apt install -y apache2-doc ssl-cert

# Enable essential modules
sudo a2enmod rewrite ssl headers deflate expires security2 http2

# Create necessary directories
sudo mkdir -p /var/www/html
sudo mkdir -p /var/log/apache2

# Set proper permissions
sudo chown -R www-data:www-data /var/www/html
sudo chown -R www-data:www-data /var/log/apache2

# Enable and start service
sudo systemctl enable --now apache2

# Verify installation
apache2ctl -v
sudo systemctl status apache2
```

### Arch Linux

```bash
# Install Apache
sudo pacman -S apache

# Install additional modules
sudo pacman -S apache-mod-security apache-mod-wsgi

# Create apache user if not exists
sudo useradd -r -d /srv/http -s /sbin/nologin -c "Apache HTTP Server" apache

# Create necessary directories
sudo mkdir -p /etc/httpd/conf.d
sudo mkdir -p /var/log/httpd
sudo mkdir -p /srv/http

# Set proper permissions
sudo chown -R apache:apache /srv/http
sudo chown -R apache:apache /var/log/httpd

# Edit main configuration
sudo sed -i 's/#ServerName www.example.com:80/ServerName localhost:80/' /etc/httpd/conf/httpd.conf

# Enable and start service
sudo systemctl enable --now httpd

# Verify installation
httpd -v
sudo systemctl status httpd
```

### Alpine Linux

```bash
# Install Apache
apk add --no-cache apache2 apache2-ssl apache2-utils

# Install additional modules
apk add --no-cache apache2-mod-wsgi apache2-mod-fcgid

# Create apache user if not exists
adduser -D -H -s /sbin/nologin -g apache apache

# Create necessary directories
mkdir -p /var/www/localhost/htdocs
mkdir -p /var/log/apache2
mkdir -p /run/apache2

# Set proper permissions
chown -R apache:apache /var/www/localhost/htdocs
chown -R apache:apache /var/log/apache2
chown -R apache:apache /run/apache2

# Configure basic settings
sed -i 's/#ServerName www.example.com:80/ServerName localhost:80/' /etc/apache2/httpd.conf

# Enable and start service
rc-update add apache2 default
rc-service apache2 start

# Verify installation
httpd -v
rc-service apache2 status
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y apache2 apache2-mod_ssl apache2-utils

# Install additional modules
sudo zypper install -y apache2-mod_security2 apache2-mod_wsgi

# SLES 15
# Enable web and scripting module
sudo SUSEConnect -p sle-module-web-scripting/15.5/x86_64
sudo zypper install -y apache2 apache2-mod_ssl

# Create necessary directories
sudo mkdir -p /etc/apache2/conf.d
sudo mkdir -p /var/log/apache2
sudo mkdir -p /srv/www/htdocs

# Set proper permissions
sudo chown -R wwwrun:www /srv/www/htdocs
sudo chown -R wwwrun:www /var/log/apache2

# Enable modules
sudo a2enmod ssl
sudo a2enmod rewrite
sudo a2enmod headers

# Enable and start service
sudo systemctl enable --now apache2

# Verify installation
apache2ctl -v
sudo systemctl status apache2
```

### macOS

```bash
# Using Homebrew
brew install httpd

# Start as service
brew services start httpd

# Or run manually
sudo /usr/local/bin/httpd -D FOREGROUND

# Configuration location: /usr/local/etc/httpd/httpd.conf
# Alternative: /opt/homebrew/etc/httpd/httpd.conf (Apple Silicon)

# Create necessary directories
sudo mkdir -p /usr/local/var/log/httpd
sudo mkdir -p /usr/local/var/www

# Set basic configuration
sed -i '' 's/#ServerName www.example.com:8080/ServerName localhost:8080/' /usr/local/etc/httpd/httpd.conf

# Verify installation
/usr/local/bin/httpd -v
brew services list | grep httpd
```

### FreeBSD

```bash
# Using pkg
pkg install apache24

# Using ports
cd /usr/ports/www/apache24
make install clean

# Enable in rc.conf
echo 'apache24_enable="YES"' >> /etc/rc.conf

# Create necessary directories
mkdir -p /var/log/httpd
mkdir -p /usr/local/www/apache24/data

# Set proper permissions
chown -R www:www /usr/local/www/apache24/data
chown -R www:www /var/log/httpd

# Start service
service apache24 start

# Verify installation
/usr/local/sbin/httpd -v
service apache24 status

# Configuration location: /usr/local/etc/apache24/httpd.conf
```

### Windows

```powershell
# Method 1: Using Chocolatey
choco install apache-httpd

# Method 2: Using Scoop
scoop bucket add extras
scoop install apache

# Method 3: Manual installation from Apache Lounge
# Download from https://www.apachelounge.com/download/
# Extract to C:\Apache24

# Install as Windows service
C:\Apache24\bin\httpd.exe -k install -n Apache24

# Start service
Start-Service Apache24

# Or using net command
net start Apache24

# Configuration location: C:\Apache24\conf\httpd.conf
# Document root: C:\Apache24\htdocs

# Verify installation
C:\Apache24\bin\httpd.exe -v
Get-Service Apache24
```

## Initial Configuration

### First-Run Setup

1. **Create apache user** (if not created by package):
```bash
# Linux systems
sudo useradd -r -d /var/www -s /sbin/nologin -c "Apache HTTP Server" apache
```

2. **Default configuration locations**:
- RHEL/CentOS/Rocky/AlmaLinux: `/etc/httpd/conf/httpd.conf`
- Debian/Ubuntu: `/etc/apache2/apache2.conf`
- Arch Linux: `/etc/httpd/conf/httpd.conf`
- Alpine Linux: `/etc/apache2/httpd.conf`
- openSUSE/SLES: `/etc/apache2/httpd.conf`
- macOS: `/usr/local/etc/httpd/httpd.conf`
- FreeBSD: `/usr/local/etc/apache24/httpd.conf`
- Windows: `C:\Apache24\conf\httpd.conf`

3. **Essential settings to change**:

```apache
# Basic security settings
ServerTokens Prod
ServerSignature Off

# Set server name
ServerName localhost:80

# Basic security modules
LoadModule headers_module modules/mod_headers.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule ssl_module modules/mod_ssl.so

# Security headers
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"

# Hide .htaccess files
<FilesMatch "^\.ht">
    Require all denied
</FilesMatch>

# Disable directory browsing by default
Options -Indexes

# Basic virtual host
<VirtualHost *:80>
    ServerName localhost
    DocumentRoot /var/www/html
    ErrorLog logs/error_log
    CustomLog logs/access_log common
</VirtualHost>
```

### Testing Initial Setup

```bash
# Test configuration syntax
sudo apache2ctl configtest  # Debian/Ubuntu
sudo httpd -t               # RHEL/CentOS/Arch

# Check loaded modules
apache2ctl -M  # Debian/Ubuntu
httpd -M       # RHEL/CentOS/Arch

# Test HTTP response
curl -I http://localhost

# Check if Apache is listening
sudo ss -tlnp | grep :80
sudo netstat -tlnp | grep :80

# View virtual host configuration
apache2ctl -S  # Debian/Ubuntu
httpd -S       # RHEL/CentOS/Arch
```

**WARNING:** Never expose Apache to the public internet without proper security hardening!

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable Apache to start on boot
sudo systemctl enable apache2  # Debian/Ubuntu
sudo systemctl enable httpd    # RHEL/CentOS/Arch

# Start Apache
sudo systemctl start apache2   # Debian/Ubuntu
sudo systemctl start httpd     # RHEL/CentOS/Arch

# Stop Apache
sudo systemctl stop apache2    # Debian/Ubuntu
sudo systemctl stop httpd      # RHEL/CentOS/Arch

# Restart Apache
sudo systemctl restart apache2 # Debian/Ubuntu
sudo systemctl restart httpd   # RHEL/CentOS/Arch

# Graceful reload (reload config without dropping connections)
sudo systemctl reload apache2  # Debian/Ubuntu
sudo systemctl reload httpd    # RHEL/CentOS/Arch

# Check status
sudo systemctl status apache2  # Debian/Ubuntu
sudo systemctl status httpd    # RHEL/CentOS/Arch

# View logs
sudo journalctl -u apache2 -f  # Debian/Ubuntu
sudo journalctl -u httpd -f    # RHEL/CentOS/Arch
```

### OpenRC (Alpine Linux)

```bash
# Enable Apache to start on boot
rc-update add apache2 default

# Start Apache
rc-service apache2 start

# Stop Apache
rc-service apache2 stop

# Restart Apache
rc-service apache2 restart

# Graceful reload
rc-service apache2 reload

# Check status
rc-service apache2 status

# View logs
tail -f /var/log/apache2/error.log
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'apache24_enable="YES"' >> /etc/rc.conf

# Start Apache
service apache24 start

# Stop Apache
service apache24 stop

# Restart Apache
service apache24 restart

# Graceful reload
service apache24 graceful

# Check status
service apache24 status

# View configuration test
service apache24 configtest
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start httpd
brew services stop httpd
brew services restart httpd

# Check status
brew services list | grep httpd

# Manual control
sudo /usr/local/bin/httpd -k start
sudo /usr/local/bin/httpd -k stop
sudo /usr/local/bin/httpd -k restart
sudo /usr/local/bin/httpd -k graceful

# Test configuration
/usr/local/bin/httpd -t
```

### Windows Service Manager

```powershell
# Start Apache service
Start-Service Apache24
# Or: net start Apache24

# Stop Apache service
Stop-Service Apache24
# Or: net stop Apache24

# Restart Apache service
Restart-Service Apache24

# Check status
Get-Service Apache24

# Manual control
C:\Apache24\bin\httpd.exe -k start
C:\Apache24\bin\httpd.exe -k stop
C:\Apache24\bin\httpd.exe -k restart

# Test configuration
C:\Apache24\bin\httpd.exe -t

# View logs
Get-Content C:\Apache24\logs\error.log -Wait
```

## Advanced Configuration

### Virtual Hosts

```apache
# /etc/apache2/sites-available/example.com.conf (Debian/Ubuntu)
# /etc/httpd/conf.d/example.com.conf (RHEL/CentOS)

<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/example.com/public_html
    
    # Logging
    ErrorLog ${APACHE_LOG_DIR}/example.com_error.log
    CustomLog ${APACHE_LOG_DIR}/example.com_access.log combined
    
    # Security
    <Directory /var/www/example.com/public_html>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
        
        # Hide sensitive files
        <Files ~ "^\.(htaccess|htpasswd|env)$">
            Require all denied
        </Files>
    </Directory>
</VirtualHost>

# SSL Virtual Host
<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/example.com/public_html
    
    # SSL Configuration
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem
    
    # Modern SSL configuration
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off
    SSLSessionTickets off
    
    # Security headers
    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    
    # Logging
    ErrorLog ${APACHE_LOG_DIR}/example.com_ssl_error.log
    CustomLog ${APACHE_LOG_DIR}/example.com_ssl_access.log combined
</VirtualHost>
```

### 8. Performance Tuning

```apache
# MPM Event configuration (modern and efficient)
<IfModule mpm_event_module>
    StartServers             3
    MinSpareThreads         75
    MaxSpareThreads        250
    ThreadsPerChild         25
    MaxRequestWorkers      400
    MaxConnectionsPerChild   0
    ThreadLimit             64
</IfModule>

# Compression
<IfModule mod_deflate.c>
    SetOutputFilter DEFLATE
    AddOutputFilterByType DEFLATE text/html text/css text/javascript text/xml text/plain
    AddOutputFilterByType DEFLATE application/javascript application/xml+rss application/xml
    AddOutputFilterByType DEFLATE application/json application/x-javascript
    
    # Don't compress images
    SetEnvIfNoCase Request_URI \.(?:gif|jpe?g|png|webp)$ no-gzip
    SetEnvIfNoCase Request_URI \.(?:exe|t?gz|zip|bz2|sit|rar)$ no-gzip
</IfModule>

# Caching
<IfModule mod_expires.c>
    ExpiresActive On
    ExpiresByType image/jpg "access plus 1 year"
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/gif "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/webp "access plus 1 year"
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/pdf "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType application/x-javascript "access plus 1 month"
    ExpiresByType image/x-icon "access plus 1 year"
    ExpiresDefault "access plus 2 days"
</IfModule>
```

### Security Hardening

```apache
# Security configuration
ServerTokens Prod
ServerSignature Off

# Disable unnecessary HTTP methods
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>

# Hide server information
Header always unset Server
Header unset X-Powered-By

# Security headers
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Disable TRACE method
TraceEnable off

# Timeout settings
Timeout 60
KeepAliveTimeout 15

# Request limits
LimitRequestBody 10485760  # 10MB
LimitRequestFields 100
LimitRequestFieldSize 8190
LimitRequestLine 4094

# Hide sensitive files
<FilesMatch "^\.">
    Require all denied
</FilesMatch>

<FilesMatch "\.(bak|backup|swp|tmp|~)$">
    Require all denied
</FilesMatch>

# Disable server-status and server-info
<Location "/server-status">
    Require ip 127.0.0.1
    Require ip ::1
</Location>

<Location "/server-info">
    Require ip 127.0.0.1
    Require ip ::1
</Location>
```

## Reverse Proxy Setup

### nginx as Frontend Proxy

```nginx
# /etc/nginx/sites-available/apache-proxy
upstream apache_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com www.example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        proxy_pass http://apache_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Handle Apache redirects
        proxy_redirect http://apache_backend https://$server_name;
    }
    
    # Serve static files directly with nginx
    location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        try_files $uri @apache;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
    
    location @apache {
        proxy_pass http://apache_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### HAProxy Configuration

```haproxy
# /etc/haproxy/haproxy.cfg
global
    maxconn 4096
    log stdout local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option log-health-checks
    timeout connect 5000
    timeout client 50000
    timeout server 50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

frontend apache_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/example.com.pem
    
    # Redirect HTTP to HTTPS
    redirect scheme https if !{ ssl_fc }
    
    # Security headers
    http-response set-header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
    http-response set-header X-Frame-Options SAMEORIGIN
    http-response set-header X-Content-Type-Options nosniff
    
    default_backend apache_servers

backend apache_servers
    balance roundrobin
    option httpchk GET / HTTP/1.1\r\nHost:\ localhost
    server apache1 127.0.0.1:8080 check
    server apache2 127.0.0.1:8081 check backup
```

### Caddy Configuration

```caddyfile
example.com www.example.com {
    reverse_proxy localhost:8080
    
    # Security headers
    header {
        Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        X-XSS-Protection "1; mode=block"
    }
    
    # Compression
    encode gzip
    
    # Logging
    log {
        output file /var/log/caddy/example.com.log
        level INFO
    }
}
```

### Apache as Reverse Proxy

```apache
# Enable required modules
LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_balancer_module modules/mod_proxy_balancer.so

<VirtualHost *:80>
    ServerName example.com
    
    # Proxy configuration
    ProxyPreserveHost On
    ProxyPass / http://backend-server:8080/
    ProxyPassReverse / http://backend-server:8080/
    
    # Load balancing
    ProxyPass /app/ balancer://mycluster/
    ProxyPassReverse /app/ balancer://mycluster/
    
    <Proxy balancer://mycluster>
        BalancerMember http://backend1:8080
        BalancerMember http://backend2:8080
        ProxySet hcmethod GET
        ProxySet hcuri /health
    </Proxy>
    
    # Balancer manager
    <Location "/balancer-manager">
        SetHandler balancer-manager
        Require ip 127.0.0.1
        Require ip ::1
    </Location>
</VirtualHost>
```

## Security Configuration

### SSL/TLS Configuration

```apache
# Load SSL module
LoadModule ssl_module modules/mod_ssl.so

# Global SSL configuration
SSLEngine on
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder off
SSLSessionCache shmcb:/var/run/ssl_scache(512000)
SSLSessionCacheTimeout 300
SSLUseStapling On
SSLStaplingCache shmcb:/var/run/ocsp(128000)
SSLCompression off
SSLSessionTickets off

# Generate DH parameters
# openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
SSLOpenSSLConfCmd DHParameters /etc/ssl/certs/dhparam.pem
```

### ModSecurity WAF

```bash
# Install ModSecurity
# Ubuntu/Debian
sudo apt install libapache2-mod-security2

# RHEL/CentOS
sudo dnf install mod_security

# Enable module
sudo a2enmod security2  # Ubuntu/Debian

# Download OWASP Core Rule Set
sudo mkdir -p /etc/modsecurity
cd /etc/modsecurity
sudo wget https://github.com/coreruleset/coreruleset/archive/v3.3.4.tar.gz
sudo tar xzf v3.3.4.tar.gz
sudo mv coreruleset-3.3.4 crs
sudo cp crs/crs-setup.conf.example crs/crs-setup.conf
```

```apache
# ModSecurity configuration
<IfModule mod_security2.c>
    SecRuleEngine On
    SecRequestBodyAccess On
    SecRequestBodyLimit 13107200
    SecRequestBodyNoFilesLimit 131072
    SecRequestBodyInMemoryLimit 131072
    SecRequestBodyLimitAction Reject
    SecResponseBodyAccess Off
    SecDebugLog /var/log/apache2/modsec_debug.log
    SecDebugLogLevel 0
    SecAuditEngine RelevantOnly
    SecAuditLogRelevantStatus "^(?:5|4(?!04))"
    SecAuditLogParts ABDEFHIJZ
    SecAuditLogType Serial
    SecAuditLog /var/log/apache2/modsec_audit.log
    
    # Include OWASP Core Rule Set
    Include /etc/modsecurity/crs/crs-setup.conf
    Include /etc/modsecurity/crs/rules/*.conf
</IfModule>
```

### Firewall Rules

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 'Apache Full'    # HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# firewalld (RHEL/CentOS/openSUSE)
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4

# pf (FreeBSD)
# Add to /etc/pf.conf
pass in on $ext_if proto tcp from any to any port {80, 443}

# Windows Firewall
New-NetFirewallRule -DisplayName "Apache HTTP" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
New-NetFirewallRule -DisplayName "Apache HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
```

### Access Control

```apache
# IP-based access control
<Directory "/var/www/admin">
    Require ip 192.168.1.0/24
    Require ip 127.0.0.1
    Require ip ::1
</Directory>

# Password protection
<Directory "/var/www/private">
    AuthType Basic
    AuthName "Restricted Area"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Directory>

# Create password file
# htpasswd -c /etc/apache2/.htpasswd username

# Client certificate authentication
<Directory "/var/www/secure">
    SSLRequireSSL
    SSLVerifyClient require
    SSLVerifyDepth 1
    SSLCACertificateFile /etc/ssl/certs/ca.crt
</Directory>
```

## Database Setup

Apache HTTP Server doesn't require a database, but it commonly integrates with databases through various modules and applications:

### PHP Database Integration

```apache
# PHP module configuration
LoadModule php_module modules/libphp.so

<IfModule mod_php.c>
    AddType application/x-httpd-php .php
    php_admin_flag allow_url_include Off
    php_admin_flag allow_url_fopen Off
    php_admin_value upload_max_filesize 64M
    php_admin_value post_max_size 64M
    php_admin_value memory_limit 256M
    php_admin_value max_execution_time 300
    php_admin_flag expose_php Off
</IfModule>
```

### Database Connection Examples

```apache
# Environment variables for database connections
SetEnv DB_HOST localhost
SetEnv DB_NAME myapp
SetEnv DB_USER webapp
SetEnv DB_PASS secretpassword

# Secure environment variables from external access
<Location "/server-status">
    SetHandler server-status
    Require local
</Location>
```

### CGI Database Applications

```apache
# Enable CGI for database applications
LoadModule cgi_module modules/mod_cgi.so

<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options +ExecCGI
    AddHandler cgi-script .cgi .pl .py
    Require all granted
</Directory>

# Python WSGI for database applications
LoadModule wsgi_module modules/mod_wsgi.so

WSGIDaemonProcess myapp python-home=/path/to/venv python-path=/path/to/app
WSGIProcessGroup myapp
WSGIScriptAlias / /path/to/app/app.wsgi
```

## Performance Optimization

### System-level Tuning

```bash
# Increase system limits for Apache
sudo tee -a /etc/security/limits.conf <<EOF
apache soft nofile 65535
apache hard nofile 65535
www-data soft nofile 65535
www-data hard nofile 65535
EOF

# Kernel optimization for web servers
sudo tee -a /etc/sysctl.conf <<EOF
# Apache optimization
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 15000 65000
fs.file-max = 100000

# Memory management
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF

sudo sysctl -p
```

### Apache Performance Settings

```apache
# Optimized MPM Event configuration
<IfModule mpm_event_module>
    StartServers             4
    MinSpareThreads         25
    MaxSpareThreads        75 
    ThreadsPerChild         25
    MaxRequestWorkers      400
    MaxConnectionsPerChild   0
    ThreadLimit             64
    ServerLimit             16
    AsyncRequestWorkerFactor 2
</IfModule>

# Connection settings
KeepAlive On
KeepAliveTimeout 15
MaxKeepAliveRequests 100

# Timeout settings
Timeout 60
LimitRequestLine 4094
LimitRequestFieldSize 8190
LimitRequestFields 100
LimitRequestBody 10485760

# Buffer settings
EnableSendfile On
EnableMMAP On
```

### Caching Configuration

```apache
# Enable caching modules
LoadModule cache_module modules/mod_cache.so
LoadModule cache_disk_module modules/mod_cache_disk.so

# Disk cache configuration
<IfModule mod_cache_disk.c>
    CacheRoot /var/cache/apache2
    CacheDirLevels 2
    CacheDirLength 1
    CacheEnable disk /
    CacheIgnoreHeaders Set-Cookie
    CacheDefaultExpire 3600
    CacheMaxExpire 86400
    CacheLastModifiedFactor 0.1
    CacheHeader on
</IfModule>

# Memory cache (alternative to disk cache)
LoadModule cache_socache_module modules/mod_cache_socache.so

<IfModule mod_cache_socache.c>
    CacheEnable socache /
    CacheSocache shmcb
    CacheSocacheMaxSize 102400
</IfModule>
```

### Content Optimization

```apache
# Compression
<IfModule mod_deflate.c>
    SetOutputFilter DEFLATE
    AddOutputFilterByType DEFLATE text/html text/css text/javascript text/xml text/plain
    AddOutputFilterByType DEFLATE application/javascript application/xml+rss application/xml
    AddOutputFilterByType DEFLATE application/json application/x-javascript application/xhtml+xml
    
    # Don't compress images or binaries
    SetEnvIfNoCase Request_URI \.(?:gif|jpe?g|png|webp|pdf|zip|rar|exe)$ no-gzip
    
    # Compression level (1-9, 6 is good balance)
    DeflateCompressionLevel 6
</IfModule>

# Static file caching
<IfModule mod_expires.c>
    ExpiresActive On
    
    # Images
    ExpiresByType image/jpg "access plus 1 year"
    ExpiresByType image/jpeg "access plus 1 year"
    ExpiresByType image/gif "access plus 1 year"
    ExpiresByType image/png "access plus 1 year"
    ExpiresByType image/webp "access plus 1 year"
    ExpiresByType image/svg+xml "access plus 1 year"
    
    # CSS and JavaScript
    ExpiresByType text/css "access plus 1 month"
    ExpiresByType application/javascript "access plus 1 month"
    ExpiresByType application/x-javascript "access plus 1 month"
    
    # Fonts
    ExpiresByType font/woff "access plus 1 year"
    ExpiresByType font/woff2 "access plus 1 year"
    ExpiresByType application/font-woff "access plus 1 year"
    ExpiresByType application/font-woff2 "access plus 1 year"
    
    # Icons
    ExpiresByType image/x-icon "access plus 1 year"
    ExpiresByType image/vnd.microsoft.icon "access plus 1 year"
    
    # HTML
    ExpiresByType text/html "access plus 300 seconds"
    
    # Default
    ExpiresDefault "access plus 1 day"
</IfModule>
```

## Monitoring

### Built-in Monitoring

```apache
# Enable server-status module
LoadModule status_module modules/mod_status.so

<Location "/server-status">
    SetHandler server-status
    Require ip 127.0.0.1
    Require ip ::1
</Location>

<Location "/server-info">
    SetHandler server-info
    Require ip 127.0.0.1
    Require ip ::1
</Location>

# Extended status
ExtendedStatus On
```

### Log Analysis

```bash
# Monitor Apache access logs
tail -f /var/log/apache2/access.log  # Debian/Ubuntu
tail -f /var/log/httpd/access_log    # RHEL/CentOS

# Monitor error logs
tail -f /var/log/apache2/error.log   # Debian/Ubuntu
tail -f /var/log/httpd/error_log     # RHEL/CentOS

# Analyze top IPs
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -10

# Analyze response codes
awk '{print $9}' /var/log/apache2/access.log | sort | uniq -c | sort -rn

# Analyze most requested files
awk '{print $7}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -10

# Check for errors
grep "error" /var/log/apache2/error.log | tail -10
```

### External Monitoring Tools

```bash
# Install monitoring tools
# GoAccess for real-time log analysis
sudo apt install goaccess  # Ubuntu/Debian
sudo dnf install goaccess  # RHEL/CentOS

# Real-time analysis
goaccess /var/log/apache2/access.log -c

# Generate HTML report
goaccess /var/log/apache2/access.log -o /var/www/html/stats.html --log-format=COMBINED --real-time-html

# Install htop for process monitoring
sudo apt install htop
htop -p $(pgrep apache2 | head -5 | tr '\n' ',' | sed 's/,$//')
```

### Performance Monitoring

```bash
# Monitor Apache processes
ps aux | grep apache2 | grep -v grep

# Monitor memory usage
ps aux --sort=-%mem | grep apache2 | head -10

# Monitor connection counts
ss -tan | grep :80 | wc -l
ss -tan | grep :443 | wc -l

# Check server-status (if enabled)
curl http://localhost/server-status
curl http://localhost/server-status?auto  # Machine readable

# Monitor file descriptors
lsof -u apache2 | wc -l  # Ubuntu/Debian
lsof -u apache | wc -l   # RHEL/CentOS
```

## 9. Backup and Restore

### 4. Configuration Backup

```bash
#!/bin/bash
# backup-apache-config.sh

BACKUP_DIR="/backup/apache/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Detect Apache configuration directory
if [ -d /etc/apache2 ]; then
    # Debian/Ubuntu
    CONFIG_DIR="/etc/apache2"
    LOG_DIR="/var/log/apache2"
    WEB_DIR="/var/www"
elif [ -d /etc/httpd ]; then
    # RHEL/CentOS
    CONFIG_DIR="/etc/httpd"
    LOG_DIR="/var/log/httpd"
    WEB_DIR="/var/www"
fi

# Backup Apache configuration
tar czf "$BACKUP_DIR/apache-config.tar.gz" -C / "${CONFIG_DIR#/}"

# Backup website files
tar czf "$BACKUP_DIR/apache-sites.tar.gz" -C "$WEB_DIR" .

# Backup SSL certificates
if [ -d /etc/letsencrypt ]; then
    tar czf "$BACKUP_DIR/ssl-certs.tar.gz" -C /etc letsencrypt
fi

# Backup recent logs (last 7 days)
find "$LOG_DIR" -name "*.log" -mtime -7 -exec tar czf "$BACKUP_DIR/apache-logs.tar.gz" {} +

# Package version info
if command -v apache2ctl &> /dev/null; then
    apache2ctl -v > "$BACKUP_DIR/version.txt"
elif command -v httpd &> /dev/null; then
    httpd -v > "$BACKUP_DIR/version.txt"
fi

echo "Backup completed: $BACKUP_DIR"
```

### Website Backup

```bash
#!/bin/bash
# backup-websites.sh

BACKUP_DIR="/backup/websites/$(date +%Y%m%d_%H%M%S)"
WEB_ROOT="/var/www/html"

mkdir -p "$BACKUP_DIR"

# Backup all websites
for site in "$WEB_ROOT"/*; do
    if [ -d "$site" ]; then
        site_name=$(basename "$site")
        echo "Backing up $site_name..."
        tar czf "$BACKUP_DIR/${site_name}.tar.gz" -C "$WEB_ROOT" "$site_name"
    fi
done

# Backup databases (if applicable)
if command -v mysqldump &> /dev/null; then
    for db in $(mysql -e "SHOW DATABASES;" | grep -v -E "^(Database|information_schema|performance_schema|mysql|sys)$"); do
        mysqldump "$db" | gzip > "$BACKUP_DIR/${db}.sql.gz"
    done
fi

# Keep only last 30 days of backups
find /backup/websites -type d -mtime +30 -exec rm -rf {} + 2>/dev/null

echo "Website backup completed: $BACKUP_DIR"
```

### Restore Procedures

```bash
#!/bin/bash
# restore-apache.sh

BACKUP_DIR="$1"
if [ -z "$BACKUP_DIR" ]; then
    echo "Usage: $0 <backup-directory>"
    exit 1
fi

# Stop Apache
if command -v systemctl &> /dev/null; then
    sudo systemctl stop apache2 || sudo systemctl stop httpd
elif command -v service &> /dev/null; then
    sudo service apache2 stop || sudo service httpd stop
fi

# Restore configuration
if [ -f "$BACKUP_DIR/apache-config.tar.gz" ]; then
    sudo tar xzf "$BACKUP_DIR/apache-config.tar.gz" -C /
    echo "Configuration restored"
fi

# Restore websites
if [ -f "$BACKUP_DIR/apache-sites.tar.gz" ]; then
    sudo tar xzf "$BACKUP_DIR/apache-sites.tar.gz" -C /var/www
    echo "Websites restored"
fi

# Restore SSL certificates
if [ -f "$BACKUP_DIR/ssl-certs.tar.gz" ]; then
    sudo tar xzf "$BACKUP_DIR/ssl-certs.tar.gz" -C /etc
    echo "SSL certificates restored"
fi

# Test configuration
if command -v apache2ctl &> /dev/null; then
    sudo apache2ctl configtest
    if [ $? -eq 0 ]; then
        sudo systemctl start apache2
    fi
elif command -v httpd &> /dev/null; then
    sudo httpd -t
    if [ $? -eq 0 ]; then
        sudo systemctl start httpd
    fi
fi

echo "Restore completed"
```

### Automated Backup

```bash
# Create cron job for daily backups
sudo tee /etc/cron.d/apache-backup <<EOF
# Apache daily backup
0 2 * * * root /usr/local/bin/backup-apache-config.sh
0 3 * * * root /usr/local/bin/backup-websites.sh
EOF

# Make scripts executable
sudo chmod +x /usr/local/bin/backup-apache-config.sh
sudo chmod +x /usr/local/bin/backup-websites.sh
```

## 6. Troubleshooting

### Common Issues

1. **Apache won't start**:
```bash
# Check configuration syntax
sudo apache2ctl configtest  # Debian/Ubuntu
sudo httpd -t               # RHEL/CentOS

# Check error logs
sudo tail -20 /var/log/apache2/error.log  # Debian/Ubuntu
sudo tail -20 /var/log/httpd/error_log    # RHEL/CentOS

# Check port conflicts
sudo ss -tlnp | grep :80
sudo lsof -i :80

# Check permissions
ls -la /var/www/html
ps aux | grep apache2
```

2. **Permission denied errors**:
```bash
# Fix ownership
sudo chown -R www-data:www-data /var/www/html  # Debian/Ubuntu
sudo chown -R apache:apache /var/www/html      # RHEL/CentOS

# Fix permissions
sudo find /var/www/html -type d -exec chmod 755 {} \;
sudo find /var/www/html -type f -exec chmod 644 {} \;

# Check SELinux (RHEL/CentOS)
getenforce
sudo setsebool -P httpd_can_network_connect 1
sudo restorecon -Rv /var/www/html
```

3. **Virtual host not working**:
```bash
# Check virtual host configuration
apache2ctl -S  # Debian/Ubuntu
httpd -S       # RHEL/CentOS

# Enable virtual host (Debian/Ubuntu)
sudo a2ensite example.com.conf
sudo systemctl reload apache2

# Test virtual host
curl -H "Host: example.com" http://localhost/
```

4. **SSL certificate issues**:
```bash
# Check certificate files
sudo openssl x509 -in /etc/ssl/certs/example.com.crt -text -noout

# Test SSL configuration
echo | openssl s_client -servername example.com -connect example.com:443

# Check SSL module
apache2ctl -M | grep ssl  # Debian/Ubuntu
httpd -M | grep ssl       # RHEL/CentOS
```

### Debug Mode

```apache
# Enable debug logging
LogLevel debug

# Module-specific debug
LogLevel ssl:debug
LogLevel rewrite:debug

# Custom debug log format
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\" %D" debug
CustomLog /var/log/apache2/debug.log debug
```

### Performance Issues

```bash
# Monitor Apache processes
top -p $(pgrep apache2 | head -5 | tr '\n' ',' | sed 's/,$//')

# Check memory usage
ps aux --sort=-%mem | grep apache2

# Monitor connections
watch 'ss -tan | grep :80 | wc -l'

# Check slow queries (if applicable)
grep "taking too long" /var/log/apache2/error.log

# Analyze configuration
apache2ctl -t -D DUMP_VHOSTS
apache2ctl -t -D DUMP_MODULES
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf check-update httpd
sudo dnf update httpd httpd-tools mod_ssl

# Debian/Ubuntu
sudo apt update
sudo apt upgrade apache2 apache2-utils libapache2-mod-ssl

# Arch Linux
sudo pacman -Syu apache

# Alpine Linux
apk update
apk upgrade apache2

# openSUSE
sudo zypper update apache2

# FreeBSD
pkg update
pkg upgrade apache24

# macOS
brew upgrade httpd

# Always test configuration after update
sudo apache2ctl configtest  # Debian/Ubuntu
sudo httpd -t               # RHEL/CentOS

# Graceful restart to apply updates
sudo systemctl reload apache2  # Debian/Ubuntu
sudo systemctl reload httpd    # RHEL/CentOS
```

### Log Rotation

```bash
# Configure log rotation for Apache
sudo tee /etc/logrotate.d/apache2 <<EOF
/var/log/apache2/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        if /bin/pidof apache2 > /dev/null ; then \
            /usr/sbin/apache2ctl graceful > /dev/null; \
        fi
    endscript
}
EOF

# For RHEL/CentOS
sudo tee /etc/logrotate.d/httpd <<EOF
/var/log/httpd/*log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        /bin/systemctl reload httpd.service > /dev/null 2>/dev/null || true
    endscript
}
EOF
```

### Health Checks

```bash
#!/bin/bash
# apache-health-check.sh

# Check if Apache is running
if ! pgrep apache2 > /dev/null && ! pgrep httpd > /dev/null; then
    echo "CRITICAL: Apache is not running"
    exit 2
fi

# Check if Apache responds to HTTP requests
if ! curl -f -s http://localhost > /dev/null; then
    echo "CRITICAL: Apache not responding to HTTP requests"
    exit 2
fi

# Check configuration syntax
if command -v apache2ctl &> /dev/null; then
    if ! apache2ctl configtest &> /dev/null; then
        echo "WARNING: Apache configuration has syntax errors"
        exit 1
    fi
elif command -v httpd &> /dev/null; then
    if ! httpd -t &> /dev/null; then
        echo "WARNING: Apache configuration has syntax errors"
        exit 1
    fi
fi

# Check disk space for logs
LOG_USAGE=$(df /var/log | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$LOG_USAGE" -gt 90 ]; then
    echo "WARNING: Log directory is ${LOG_USAGE}% full"
    exit 1
fi

echo "OK: Apache is healthy"
exit 0
```

### Cleanup Tasks

```bash
# Clean old log files
find /var/log/apache2 -name "*.log.*" -mtime +30 -delete  # Debian/Ubuntu
find /var/log/httpd -name "*log.*" -mtime +30 -delete     # RHEL/CentOS

# Clean Apache cache
rm -rf /var/cache/apache2/*

# Clean temporary files
find /tmp -name "apache*" -mtime +7 -delete

# Optimize log files (remove old entries)
sudo journalctl --vacuum-time=30d
```

## Integration Examples

### PHP Integration

```bash
# Install PHP
sudo apt install php libapache2-mod-php  # Ubuntu/Debian
sudo dnf install php php-cli              # RHEL/CentOS

# Enable PHP module
sudo a2enmod php8.1  # Ubuntu/Debian

# Test PHP
echo "<?php phpinfo(); ?>" | sudo tee /var/www/html/info.php
```

### WordPress Integration

```apache
<VirtualHost *:443>
    ServerName blog.example.com
    DocumentRoot /var/www/wordpress
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/blog.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/blog.example.com/privkey.pem
    
    <Directory /var/www/wordpress>
        AllowOverride All
        Options -Indexes +FollowSymLinks
        Require all granted
    </Directory>
    
    # WordPress-specific rules
    RewriteEngine On
    RewriteRule ^/wp-admin/install.php$ - [F]
    RewriteRule ^/wp-config-sample.php$ - [F]
    
    # Security for wp-config.php
    <Files wp-config.php>
        Require all denied
    </Files>
</VirtualHost>
```

### Python WSGI Integration

```apache
# Load WSGI module
LoadModule wsgi_module modules/mod_wsgi.so

<VirtualHost *:443>
    ServerName app.example.com
    DocumentRoot /var/www/python-app
    
    WSGIDaemonProcess app python-home=/var/www/python-app/venv python-path=/var/www/python-app
    WSGIProcessGroup app
    WSGIScriptAlias / /var/www/python-app/app.wsgi
    
    <Directory /var/www/python-app>
        WSGIApplicationGroup %{GLOBAL}
        Require all granted
    </Directory>
</VirtualHost>
```

### Node.js Proxy Integration

```apache
<VirtualHost *:443>
    ServerName node.example.com
    
    ProxyPreserveHost On
    ProxyPass / http://localhost:3000/
    ProxyPassReverse / http://localhost:3000/
    
    # WebSocket support
    ProxyPass /socket.io/ ws://localhost:3000/socket.io/
    ProxyPassReverse /socket.io/ ws://localhost:3000/socket.io/
    
    # Static files served by Apache
    Alias /static /var/www/node-app/public
    <Directory /var/www/node-app/public>
        Require all granted
        ExpiresActive On
        ExpiresDefault "access plus 1 year"
    </Directory>
</VirtualHost>
```

## Additional Resources

- [Official Documentation](https://httpd.apache.org/docs/)
- [GitHub Repository](https://github.com/apache/httpd)
- [Security Guide](https://httpd.apache.org/docs/2.4/misc/security_tips.html)
- [Performance Tuning](https://httpd.apache.org/docs/2.4/misc/perf-tuning.html)
- [Apache Modules](https://httpd.apache.org/docs/2.4/mod/)
- [Virtual Hosts Guide](https://httpd.apache.org/docs/2.4/vhosts/)
- [SSL/TLS Guide](https://httpd.apache.org/docs/2.4/ssl/)
- [Community Mailing Lists](https://httpd.apache.org/lists.html)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.