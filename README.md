## Overview
## Author : Matteu Olivieri Bastiani

**injector.py** is an advanced script for **injecting payloads into writable text files** on Unix/Linux systems.  
It is designed for **authorized security testing, auditing, and research purposes**.

> ⚠️ **Disclaimer:** Use this tool only in environments where you have explicit permission. Unauthorized use is strictly prohibited.



## Features

-  **File Discovery**
  - Recursively scans directories for writable text files.
  - Filters by file extension, size, and accessibility.

-  **Injection Modes**
  - `append`: Add payload at the end.
  - `prepend`: Insert payload at the start.
  - `replace`: Overwrite the entire file content.

-  **Automatic Backup**
  - Creates `.bak` copies before modification for safety.

-  **Timestamp Restoration**
  - Preserves original access and modification times to avoid detection.

-  **Extended Attributes**
  - Optionally store payload as a hidden xattr (`user.payload` or custom key).

-  **Dry-Run Mode**
  - Lists candidate files without making any changes.

-  **Rollback Protection**
  - Automatically reverts to the original file if an error occurs.
