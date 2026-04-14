# O360 SAST for Android Studio / IntelliJ IDEA

Enterprise Static Application Security Testing (SAST) integrated directly into Android Studio and IntelliJ IDEA. Scan your project, module, or file for security vulnerabilities — results appear in a dedicated findings panel with direct code navigation to every vulnerability.

## Features

### Scan from the Tools Menu
- **Scan Project** — Scan your entire project
- **Scan Module** — Scan the currently active module
- **Scan File** — Scan the file currently open in the editor

All scan options are also accessible from the **right-click context menu** in the editor and project view.

### Security Findings Panel
- **Severity Badges** — Color-coded rows showing Critical, High, Medium, Low findings
- **Findings Table** — Sortable list with severity, vulnerability title, file name, and line number
- **Detail Panel** — Select any finding to see full description, impact analysis, and recommendation
- **Code Navigation** — Double-click any finding to open the source file and jump to the exact vulnerable line

### Multiple Scan Types
- **Code Vulnerabilities** — 20+ language engines (Java, Kotlin, JavaScript/TypeScript, Python, PHP, Go, Ruby, Swift, C/C++, and more)
- **Dependency Scanning (SCA)** — Known CVEs in Gradle, Maven, npm, and other package managers
- **License Compliance** — Open source license risk detection
- **Malware Detection** — YARA-based malware scanning

### Enterprise-Ready
- On-premises or cloud O360 SAST server
- API token authentication
- Settings via **File → Settings → Tools → O360 SAST**

## Getting Started

### Prerequisites
- **Android Studio** (Flamingo or later) or **IntelliJ IDEA** (2024.1+)
- An **O360 SAST server** instance (on-premises or cloud)
- An **API access token** (generated from the O360 dashboard)

### Installation
1. Download **o360-sast-1.0.0.zip** from the [GitHub Releases](https://github.com/offensive360/AndroidStudio/releases/latest)
2. In Android Studio: **File → Settings → Plugins → ⚙ → Install Plugin from Disk...**
3. Select the downloaded `.zip` file and restart when prompted

### Configuration
1. Go to **File → Settings → Tools → O360 SAST**
2. Set **Endpoint** — your O360 server URL (e.g. `https://your-server.com:1800`)
3. Set **Access Token** — generated from O360 dashboard → Settings → Access Tokens
4. Optionally enable **Dependency Scanning**, **License Scanning**, or **Malware Scanning**
5. Click **OK**

### First Scan
1. Open a project in Android Studio
2. Go to **Tools → O360 SAST → Scan Project**
3. Monitor progress in the background task bar
4. When complete, the **O360 Security Findings** panel opens at the bottom
5. Click any finding to see details; double-click to navigate to the vulnerable line

### Opening the Findings Panel
If the panel isn't visible: **View → Tool Windows → O360 Security Findings**

## Settings

| Setting | Description |
|---------|-------------|
| Endpoint | O360 SAST server URL (required) |
| Access Token | API access token (required) |
| Scan Dependencies | Include SCA scanning for known CVEs |
| Scan Licenses | Include open source license compliance |
| Scan Malware | Include YARA malware scanning |

## Supported Languages

Java, Kotlin, JavaScript, TypeScript, Python, PHP, Go, Ruby, Swift, Objective-C, Dart/Flutter, C/C++, C#, Apex, and more — powered by O360's proprietary deep analysis engines and AI-assisted scanning.

## Support

- Issues: [GitHub Issues](https://github.com/offensive360/AndroidStudio/issues)
- Documentation: [O360 SAST Docs](https://www.offensive360.com)
