# Offensive360 SAST Plugin for IntelliJ IDEA and Android Studio

Token-based Static Application Security Testing (SAST) plugin for IntelliJ IDEA, Android Studio, and other IntelliJ-based IDEs.

## Features

- **Token-based Authentication**: Secure connection using API tokens (no username/password)
- **Direct Project Scanning**: Scan your project from within your IDE
- **Real-time Progress**: Visual progress indicators during scanning
- **Ephemeral Scans**: Scans are not saved to database (temporary results only)
- **Easy Configuration**: Simple settings dialog for token and server URL

## Installation

1. Download the plugin JAR file
2. In IntelliJ IDEA / Android Studio: `File > Settings > Plugins > Install JAR`
3. Select the downloaded JAR file
4. Restart the IDE

## Configuration

1. Open Settings: `File > Settings > Tools > Offensive360 SAST`
2. Enter your **O360 Server URL** (e.g., `https://sast.offensive360.com`)
3. Enter your **API Access Token** (generated from O360 Dashboard → Settings → Tokens)
4. Click **Apply** and **OK**

The token must be a valid JWT starting with `ey`.

## Usage

1. **Scan Current Project**:
   - Select `Tools > Offensive360 > Scan Current Project`
   - Wait for the scan to complete
   - View results in the notifications panel

2. **Scan Git Repository**:
   - Select `Tools > Offensive360 > Scan Git Repository`
   - Enter the Git repository URL
   - Wait for results

## Architecture

- **Settings Service**: Securely stores endpoint and token in IDE configuration
- **SAST Client**: Communicates with O360 API using Bearer token authentication
- **Project Zipper**: Efficiently packages project for uploading
- **Progress Tracking**: Real-time feedback during scanning

## Key Security Features

- Developers only see results from their scans (ephemeral)
- No project browsing of server projects
- All communication uses HTTPS
- Token stored in IDE's secure configuration storage
- Validation of token before each scan

## Building

```bash
./gradlew build
```

The plugin JAR will be created in `build/distributions/`.

## Requirements

- IntelliJ IDEA 2022.1 or later
- Android Studio 2022.1 or later
- O360 Server with token-based API support

## Support

For issues or feature requests, visit [offensive360.com/contact](https://offensive360.com/contact) or open an issue on [GitHub](https://github.com/offensive360/AndroidStudio/issues).
