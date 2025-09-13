<div align="center">

### 👇

  <p>
    <a href="https://github.com/EXLOUD/windows-telemetry-disabler/archive/refs/heads/main.zip  ">
      <img src="https://img.shields.io/badge/_  >_Download_This_Script_<_-darkgreen?style=for-the-badge">
    </a>
  </p>


---

### 👀 Repository Views

  <img alt="count" src="https://count.getloli.com/get/@:EXLOUD-WIN-TELEMETRY-DISABLER?theme=rule34" />

  **⭐ If this tool helped you, please consider giving it a star! ⭐**

---

  **Language:** [English](#) | [Українська](README-UK.md)

  <h1>Windows Telemetry Disabler</h1>
  
  <p>
    <a href="https://docs.microsoft.com/en-us/windows/privacy/  ">
      <img src="https://img.shields.io/badge/Windows_Privacy-0078D4?style=for-the-badge" alt="Windows Privacy">
    </a>
  </p>
  
  <img src="assets/preview.gif" width="600" alt="Windows Telemetry Disabler demo preview">
  
  [![GitHub issues](  https://img.shields.io/github/issues/EXLOUD/windows-telemetry-disabler?style=flat-square)](  https://github.com/EXLOUD/windows-telemetry-disabler/issues  )
  ![PowerShell](https://custom-icon-badges.demolab.com/badge/PowerShell-5.0-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
  ![Windows](  https://img.shields.io/badge/Windows-10%2F11-0078D4?style=for-the-badge&logo=windows&logoColor=white)
  ![License](  https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
  ![Architecture](  https://custom-icon-badges.demolab.com/badge/Architecture-x86%20%7C%20x64%20%7C%20ARM64-blue?style=for-the-badge&logo=cpu&logoColor=white)
  [![GitHub stars](  https://img.shields.io/github/stars/EXLOUD/windows-telemetry-disabler?style=flat-square)](  https://github.com/EXLOUD/windows-telemetry-disabler/stargazers  )

  A powerful script to disable telemetry and data collection in Windows operating system. This tool runs with TrustedInstaller privileges for maximum effectiveness and supports all modern Windows architectures.

</div>

---

# Windows Telemetry Disabler

**Author:** EXLOUD  
**GitHub:** https://github.com/EXLOUD  

A script to disable telemetry and data collection in Windows operating system.

## 📋 Description

This tool allows you to disable various Windows telemetry services that collect usage data and send it to Microsoft. The script runs with elevated privileges (TrustedInstaller) for maximum effectiveness.

## 🔧 System Requirements

- **Operating System:** Windows 10/11
- **PowerShell:** version 5.0 or newer
- **Architecture:** x64, x86 (win32), ARM64
- **Privileges:** Run as Administrator

## 🛠️ Privilege Elevation Tool

This script utilizes a custom privilege escalation utility (`superUser*.exe`) to execute PowerShell commands with **TrustedInstaller-level permissions**, ensuring deep system-level changes can be applied reliably.

> **Note:** The `superUser` binaries included in this release are pre-compiled third-party utilities used temporarily for privilege escalation. Custom open-source alternatives are under development.

<p align="center">
  <a href="https://github.com/mspaintmsi/superUser">
    <img src="https://img.shields.io/badge/superUser-by_mspaintmsi-blue?style=for-the-badge&logo=github&logoColor=white" alt="superUser by mspaintmsi">
  </a>
</p>

## 📁 Project Structure

```
📂 assets  
📄 launcher.bat           # Main launcher  
📂 script/  
│   📄 telemetry-win.ps1  # Main PowerShell script  
│   📂 Tools/  
│       📂 x64/  
│       │   📄 superUser64.exe  
│       📂 win32/  
│       │   📄 superUser32.exe  
│       📂 arm64/  
│           📄 superUserA64.exe  
📄 README.md  
📄 README-UK.md  
```

## 🚀 Installation and Usage

1. **Download** all project files
2. **Extract** to any folder
3. **Run** `launcher.bat` **as Administrator**

### Step-by-step instructions:

1. Right-click on `launcher.bat`
2. Select "Run as administrator"
3. Confirm UAC prompt
4. Wait for script completion

## ⚙️ How it Works

The launcher performs the following actions:

1. **Checks for PowerShell 5 availability**
2. **Detects CPU architecture** (x64/x86/ARM64)
3. **Locates appropriate `superUser` version**
4. **Launches PowerShell script** with TrustedInstaller privileges
5. **Applies configurations** to disable telemetry

## 🛡️ What Gets Disabled

The script may disable/configure:

- Windows telemetry services
- Diagnostic data collection
- Usage data transmission to Microsoft
- Advertising identifiers
- Automatic telemetry updates
- Various scheduled tasks
- UWP background apps
- Reserved Storage
- DiagTrack logs
- CompatTelRunner.exe
- And more (see script for full list)

*For detailed list of changes, see `telemetry-win.ps1`*

## ⚠️ Important Warnings

- **Backup:** Create a system restore point before running
- **Responsibility:** Use at your own risk
- **Testing:** Test on a virtual machine first
- **Updates:** Some settings may reset after Windows updates

## 🔄 Restoring Settings

If you need to restore default settings:

1. Use system restore point
2. Or manually enable disabled services via `services.msc`
3. Restart the system

## 🆘 Troubleshooting

### Error "PowerShell 5 not found"
- Ensure PowerShell is installed
- Check path: `%SystemRoot%\System32\WindowsPowerShell\v1.0\`

### Error "superUser*.exe not found"
- Verify `superUser` files exist in `script/Tools/` subfolders
- Ensure folder structure is preserved

### Error "Unsupported CPU architecture"
- Your CPU architecture is not supported
- Contact developer to add support

## 📞 Support

- **GitHub Issues:** Create an issue in the repository
- **GitHub:**   https://github.com/EXLOUD  

## 📄 License

This project is licensed under the **MIT License**.

MIT License

Copyright (c) 2025 EXLOUD

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

<div align="center">

**Warning:** This tool modifies Windows system settings. Make sure you understand the consequences before use.

**[⬆ Back to Top](#windows-telemetry-disabler)**

</div>
