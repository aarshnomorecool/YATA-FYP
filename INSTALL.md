# YATA CLI Installation Instructions

This document explains how to install YATA as a native command-line tool.

## Prerequisites
- Python 3.8 or higher.
- `pip` package manager.

## Installation

### Install
To install YATA in editable mode:
```powershell
pip install -e .
```

### Verify Registration
Verify that the `yata` command is successfully registered with your system's path:
```powershell
Get-Command yata
```
Expected output containing:
```text
Application yata
```

### Verify
Verify the installation by running the version command:
```powershell
yata version
```

### Upgrade
To upgrade your local installation:
```powershell
pip install -e . --upgrade
```

### Uninstall
To completely remove YATA:
```powershell
pip uninstall yata
```
