# nSploit - Metasploit Module Organizer

A user-friendly web application that helps penetration testers and security professionals quickly find and organize Metasploit modules based on their testing needs.

## 🚀 Features

- **Smart Search**: Search modules by keywords, descriptions, and tags
- **Category Filtering**: Filter by module categories (Port Scanning, Vulnerability Scanning, Exploitation, etc.)
- **Target Filtering**: Filter by target types (Windows, Linux, Web, Database, etc.)
- **Quick Actions**: One-click access to common module types
- **Usage Examples**: Ready-to-use command examples for each module
- **Copy to Clipboard**: Easy copying of module paths and usage commands
- **Modern UI**: Clean, responsive interface with dark theme support

## 📋 Problem Solved

Metasploit has hundreds of modules scattered across different categories. Finding the right module for a specific task can be time-consuming and frustrating. This tool solves that by:

- Organizing modules by purpose and target type
- Providing intelligent search capabilities
- Offering ready-to-use command examples
- Making module discovery intuitive and fast

## 🛠️ Installation

1. **Clone or download the project**
   ```bash
   cd C:\Users\PJDESIGNERPC\CascadeProjects\metasploit-organizer
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Open your browser**
   Navigate to `http://localhost:5000`

## 🎯 Usage Examples

### Port Scanning
- Search for "port scan" to find all port scanning modules
- Use `auxiliary/scanner/portscan/tcp` for basic TCP scanning
- Use `auxiliary/scanner/portscan/syn` for fast SYN scanning

### SMB Testing
- Search for "smb" to find SMB-related modules
- Use `auxiliary/scanner/smb/smb_ms17_010` to check for EternalBlue
- Use `auxiliary/scanner/smb/smb_enumshares` to enumerate shares

### Web Application Testing
- Filter by "Web Scanning" category
- Use `auxiliary/scanner/http/dir_scanner` for directory enumeration
- Use `auxiliary/scanner/http/http_version` for server fingerprinting

### Vulnerability Scanning
- Filter by "Vulnerability Scanning" category
- Use `auxiliary/scanner/ssl/openssl_heartbleed` for Heartbleed testing
- Use various scanner modules for specific CVEs

## 📚 Module Categories

- **Port Scanning**: TCP, SYN, ACK port scanners
- **Service Scanning**: Version detection for various services
- **Web Scanning**: Directory enumeration, file discovery
- **Vulnerability Scanning**: CVE-specific scanners
- **Database Scanning**: MySQL, MSSQL, PostgreSQL modules
- **Brute Force**: Login scanners for various services
- **Information Gathering**: DNS enumeration, SNMP scanning
- **Exploitation**: Exploit modules for known vulnerabilities
- **Payloads**: Various payload options

## 🔧 Customization

### Adding New Modules

Edit `modules_database.py` and add new modules in this format:

```python
{
    "name": "Module Name",
    "path": "auxiliary/scanner/service/module_name",
    "category": "Service Scanning",
    "description": "What this module does",
    "targets": ["Linux", "Windows", "Network"],
    "tags": ["keyword1", "keyword2", "service"],
    "usage": "use auxiliary/scanner/service/module_name\nset RHOSTS target\nrun",
    "options": ["RHOSTS", "RPORT", "THREADS"]
}
```

### Modifying Categories

Categories are automatically generated from the modules database. To add new categories, simply use them in your module definitions.

## 🎨 Interface Features

- **Search Bar**: Type keywords to find relevant modules
- **Category Filter**: Dropdown to filter by module type
- **Target Filter**: Filter by target operating system or service
- **Quick Actions**: Buttons for common searches
- **Module Cards**: Detailed information for each module
- **Usage Examples**: Copy-paste ready commands
- **Statistics**: Live count of total modules and search results

## 🔍 Search Tips

- Use specific keywords like "smb", "http", "mysql"
- Combine search terms: "windows exploit"
- Use category filters for broad searches
- Try target filters to narrow down results
- Use quick action buttons for common tasks

## 🚨 Security Note

This tool is designed for authorized penetration testing and security research only. Always ensure you have proper authorization before testing any systems.

## 📝 License

This project is for educational and authorized security testing purposes only.

## 🤝 Contributing

Feel free to add more modules, improve the interface, or suggest new features!

## 📞 Support

If you encounter any issues or have suggestions for improvement, please create an issue or submit a pull request.
