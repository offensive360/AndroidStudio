# Offensive360 SAST - Android Studio & IntelliJ IDEA Plugin

Static Application Security Testing (SAST) plugin for Android Studio and IntelliJ IDEA. Scan your source code for security vulnerabilities directly from within your IDE, powered by the Offensive360 SAST engine.

## Features

- **Source Code Scanning** - Analyze your project for security vulnerabilities without leaving the IDE
- **Git Repository Scanning** - Scan any Git repository by URL
- **Tabbed Results Panel** - View findings organized by category with severity-coded tables
- **One-Click Navigation** - Double-click any finding to jump directly to the vulnerable line of code
- **Built-in Fix Guidance** - Vulnerability knowledge base with remediation advice
- **Dependency Scanning** - Detect known vulnerabilities in third-party libraries
- **Malware Detection** - Identify malicious code patterns in your project
- **License Compliance** - Check open-source license issues in your dependencies
- **Large Codebase Support** - Handles projects over 1 GB in size
- **Token-Based Authentication** - Secure API token authentication with the Offensive360 server

## Requirements

- **Android Studio 2024.x** or later, or **IntelliJ IDEA 2024.x** or later
- An active Offensive360 SAST server instance
- A valid API access token (generated from your Offensive360 Dashboard)

## Installation

1. Download the latest plugin ZIP from the [Releases](https://github.com/offensive360/AndroidStudio/releases) page
2. In Android Studio or IntelliJ IDEA, go to **File > Settings > Plugins**
3. Click the gear icon and select **Install Plugin from Disk...**
4. Select the downloaded ZIP file
5. Restart the IDE when prompted

## Configuration

1. Open **Settings > Tools > Offensive 360**
2. Enter your **Server URL** (e.g., `https://sast.offensive360.com`)
3. Enter your **API Access Token** (generated from your Offensive360 Dashboard under Settings > Tokens)
4. Click **Apply** and **OK**

## Usage

### Scan Current Project

- Go to **Tools > Offensive360 > Scan with Offensive360 SAST**
- Or use **Find Action** (`Ctrl+Shift+A`) and search for "Scan with Offensive360"

### Scan a Git Repository

- Go to **Tools > Offensive360 > Scan Git Repository**
- Enter the Git repository URL when prompted

### Viewing Results

Scan results are displayed in the **Offensive360 Results** tool window at the bottom of the IDE. Findings are organized into tabs by category:

- **Language Vulnerabilities** - Issues found in your source code
- **Dependency Vulnerabilities** - Known CVEs in third-party libraries
- **Malware Results** - Detected malicious code patterns
- **License Issues** - Open-source license compliance findings

Double-click any row to navigate directly to the affected file and line.

## Supported Languages

For a full list of supported languages, visit [offensive360.com](https://offensive360.com).

## Building from Source

```bash
./gradlew build
```

The plugin ZIP will be generated in `build/distributions/`.

## Support

For questions, issues, or feature requests, contact [support@offensive360.com](mailto:support@offensive360.com) or visit [offensive360.com](https://offensive360.com).
