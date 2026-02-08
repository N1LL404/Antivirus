
# Windows 10 Antivirus (Antivirus)

A robust, Python-based antivirus solution designed for Windows 10/11 systems. eScan Antivirus provides essential security features including real-time protection, on-demand scanning, firewall monitoring, and more, all wrapped in a modern user interface.

## 🛡️ Key Features

*   **Real-Time Protection**: Active monitoring of file system changes (creation, modification) to detect threats instantly.
*   **On-Demand Scanning**:
    *   **Quick Scan**: Rapidly checks common malware locations (Downloads, Desktop, System folders).
    *   **Full Scan**: Comprehensive system-wide scan.
*   **Network Firewall**: Monitors network traffic, blocking suspicious IPs and ports (e.g., standard malware ports like 4444, 5555).
*   **Heuristic Detection**: Identification of suspicious behaviors and patterns (e.g., keyloggers, remote thread creation).
*   **USB Vaccine**: Automatic monitoring and vaccination of inserted USB drives to prevent autorun malware.
*   **Gaming Mode**: Automatically detects full-screen applications to suppress notifications and optimize background resource usage.
*   **Anti-Keylogger**: Detects and alerts on potential keylogging activities.
*   **Modern GUI**: sleek, dark-themed dashboard built with `customtkinter`.
*   **System Tray Integration**: Runs quietly in the background with quick access via the system tray.

## 📋 Requirements

*   **OS**: Windows 10 or Windows 11
*   **Python**: 3.8 or higher
*   **Administrator Privileges**: Required for core protection features (file monitoring, access control).

## 🚀 Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/N1LL404/Antivirus.git
    cd Antivirus
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## 💻 Usage

To start the antivirus, simply run the `main.py` script. **Note: It is highly recommended to run the application as an Administrator** to ensure all protection modules function correctly.

```bash
python main.py
```

### Dashboard
The main dashboard provides an overview of:
*   Current system security status.
*   Quick actions for scanning.
*   Real-time logs of system activity.

### System Tray
The application minimizes to the system tray. Right-click the tray icon to:
*   Open the Dashboard.
*   Run a Quick/Full Scan.
*   Exit the application.

## ⚙️ Configuration

The application is highly configurable via `config.py`. Key settings include:

*   **Scan Settings**: Define max file size, excluded paths/extensions.
*   **Protection Levels**: Toggle Real-time protection, Firewall, etc.
*   **Backup Settings**: Configure automated backup schedules and locations.
*   **UI Customization**: Adjust theme colors and window dimensions.

## 📂 Project Structure

```text
WIN 10 ANTIVIRUS/
├── config.py           # Global configuration and constants
├── main.py             # Application entry point
├── database.py         # Database management (logs, quarantine)
├── requirements.txt    # Project dependencies
├── core/               # Core security modules
│   ├── scanner.py      # File scanning logic
│   ├── realtime.py     # Real-time monitoring
│   └── ...
├── protection/         # Specific protection features
│   ├── firewall.py     # Network firewall
│   └── keylogger...    # Anti-keylogger
├── gui/                # User Interface
│   ├── dashboard.py    # Main GUI window
│   └── tray.py         # System tray implementation
├── utilities/          # Helper utilities
│   └── gaming_mode.py  # Gaming mode logic
└── data/               # Application data (logs, quarantine, etc.)
```

## ⚠️ Disclaimer

This software is for educational and research purposes. While it implements real security concepts, it relies on signature-based and basic heuristic detection. For critical systems, always use a commercial-grade antivirus solution.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
