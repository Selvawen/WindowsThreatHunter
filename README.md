# WindowsThreatHunter
**Author:** Ben  
**Purpose:** Live Windows Threat Hunting Script for Blue Team Operations

## Overview

`ThreatHunter.ps1` is a PowerShell script designed for live threat hunting on Windows systems. It performs runtime analysis of processes, startup entries, and services to identify potentially malicious or suspicious behavior. The script is particularly useful for incident response, triage, and proactive threat detection by Blue Team or IT security professionals.

## Features

- ✅ **Process Scan**: Identifies running processes with unverified or missing digital signatures located in suspicious directories.
- ✅ **Startup Entry Scan**: Scans registry and common autorun locations for potentially unauthorized startup items.
- ✅ **Service Scan**: Analyzes Windows services for unsigned binaries or abnormal paths.
- ✅ **Report Generation**: Collects and saves findings into a CSV report.
- ✅ **Silent Error Handling**: Operates without interruption from minor errors for smoother automation.

## Prerequisites

- Windows PowerShell 5.1 or later
- Administrator privileges (recommended)

## Usage

1. Open PowerShell as Administrator.
2. Navigate to the directory containing the script.
3. Run the script:

   ```powershell
   .\ThreatHunter.ps1
After execution, a .csv report will be saved to the designated output path or the user will be notified if no suspicious items were found.

## Output

- The report is saved as a CSV file containing the following fields:

```pgsql
Time, Type, Name, Path, Extra1, Extra2
```

Each entry includes the type of threat, process or service name, file path, and additional metadata (such as process ID or digital signature status).

## Recommendations

Pay special attention to:
- Files in user directories (e.g., `C:\Users\`, `%TEMP%`, `%APPDATA%`)
- Unsigned executables
- Unknown or suspicious startup entries and services

- Steps you can take:
- Check hashes using VirusTotal or similar services
- Isolate or disable suspicious processes
- Use sandboxing tools to further investigate flagged items
- Incorporate the script into automated SOC workflows

## Limitations

- The script does not perform static or dynamic malware analysis.
- Results may include false positives, especially from unsigned legitimate applications.
- Admin rights are needed for complete visibility into all processes and services.
- Currently optimized for English-language Windows systems.

## Contribution

Contributions are welcome! Feel free to fork the project and submit a pull request for:

- Additional checks (e.g., network connections, scheduled tasks)
- Enhanced report formatting (e.g., HTML, JSON)
- Performance improvements
- Compatibility updates for future Windows versions

Please include meaningful commit messages and follow PowerShell scripting best practices.

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).  
Feel free to use, modify, and distribute with proper attribution.

---

**Disclaimer**: This tool is intended for educational, research, and internal use only. Use it responsibly and ensure it complies with your organization's security policies
