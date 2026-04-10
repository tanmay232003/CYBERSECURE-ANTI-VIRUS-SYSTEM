# CYBERSECURE-ANTI-VIRUS-SYSTEM
Built a modern light weight web-based antivirus system using Python (Flask) with SHA-256 hashing, signature-based and heuristic detection. Features real-time scanning via SSE, file upload scanner, quarantine management, and dashboard analytics. Includes modern cyber-themed UI/UX. Demonstrates full-stack development and cybersecurity fundamentals.

# DESCRIPTION OF PROJECT
Developed a web-based antivirus system using Python (Flask) that simulates core cybersecurity mechanisms including signature-based detection, heuristic analysis, and secure quarantine management.The system leverages SHA-256 hashing for file integrity checks and compares hashes against a stored signature database to identify known threats. Additionally, a heuristic detection module flags potentially malicious files based on suspicious extensions, mimicking real-world antivirus behavior.
Implemented real-time scanning using Server-Sent Events (SSE) to stream live progress updates, logs, and threat notifications to the frontend without page reloads. The application also includes a file upload scanning module, enabling users to scan individual files dynamically through the browser.

# TECH STACK
-> Backend
  - Python 3
  - Flask (Web Framework)
  - SQLite (Lightweight Database)
  - Hashlib (SHA-256 File Hashing)
  - Werkzeug (Secure Authentication & Password Hashing)
    
-> Frontend
  - HTML5, CSS3
  - Vanilla JavaScript
  - Server-Sent Events (Real-Time Updates)
  - Web Audio API (Alert Sounds)
    
-> Database Schema
  - users → stores user credentials and preferences
  - user_activity → tracks scan history and threat statistics
  - quarantined_files → manages detected and isolated threats
  - malware_signatures → maintains known malicious file hashes

# FEATURES
-> Authentication System
  - Secure Login & Signup system
  - Password hashing using Werkzeug
  - Session-based authentication
    
-> Malware Detection Engine
  - SHA-256 hash-based signature detection
  - Heuristic analysis for suspicious file types (.exe, .dll, .bat, .scr)
  - Custom signature database stored in SQLite
    
-> File & Folder Scanning
  - Scan entire directories (server-side path)
  - Upload and scan individual files
  - Real-time scan progress updates
    
-> Real-Time Scan Streaming (SSE)
  - Uses Server-Sent Events (SSE) for:
  - Live scan logs
  - Progress tracking
  - Instant threat notifications
    
-> Quarantine Management
  - Automatically isolates detected threats
  - Options to:
  - Restore files
  - Permanently delete files
    
-> Dashboard Analytics
  - Last scan timestamp
  - Daily threat count
  - Total quarantined files
    
-> Advanced UI/UX
  - Cyberpunk hacker-style UI with:
  - Animated grid background
  - Glassmorphism cards
  - Neon effects
  - Radar-style scanning animation
  - Smooth page transitions
    
-> Smart Notifications System
  - Popup alerts with emoji indicators:
✅ Safe
⚠️ Warning
💀 Critical

-> Sound alerts using Web Audio API

-> Custom Themes
  - Purple Hacker Theme
  - Windows Defender Green Theme
  - Gold Royal Theme
  - User must select theme manually (no default)
    
-> User Settings
  - Theme customization
  - Scan reminder interval
  - Notification toggle
  - Auto-update toggle (demo feature)

# UNIQUE FEATURES  (What Makes It Different)

✔ Web-Based Antivirus System
Runs entirely in a browser using Flask, unlike traditional desktop antivirus software.

✔ Real-Time Streaming Scan (SSE)
Provides live scan progress, logs, and notifications without page reloads.

✔ Advanced Interactive UI/UX System
Cyber-themed interface with animated visuals, radar scan loader, dynamic themes, and integrated sound + emoji-based threat feedback.

✔ Single-File Full Stack Architecture
Backend and frontend integrated into a single Python file for simplicity and portability.

# PROJECT GOALS
- To design and develop a web-based antivirus system using Python and Flask
- To implement core cybersecurity concepts like file hashing, signature-based detection, and heuristic analysis
- To build a real-time scanning system using Server-Sent Events (SSE)
- To create an interactive and user-friendly UI/UX for better usability
- To demonstrate full-stack development skills with database integration
- To simulate how modern antivirus systems handle threat detection and quarantine management

# FUTURE IMPROVEMENT
- AI/ML-based Threat Detection
Integrate machine learning models for advanced malware classification

- Cloud-Based Signature Updates
Fetch and update malware signatures dynamically from cloud sources

- Real-Time Background Protection
Enable continuous system monitoring instead of manual scanning

- Malicious Website Detection & Blocking
Detect and restrict access to harmful or phishing websites with real-time warning alerts

- URL Filtering & Web Protection
Implement blacklist/whitelist system to block unsafe domains and enhance safe browsing

- Browser Warning System
Show alerts when users try to access suspicious or infected websites

- Advanced File Recovery System
Restore quarantined files to original locations securely

- Role-Based Access Control (RBAC)
Add admin/user roles for better system management

- Detailed Threat Analytics Dashboard
Visualize scan history, threat trends, and system health

- Cross-Platform Deployment
Deploy as a desktop app or cloud-hosted service

# SCREENSHOT
This section showcases the user interface and core functionalities of the CyberSecure Antivirus system, including authentication, real-time scanning, and quarantine management.

-> Features Covered in Screenshots
  - Login & Signup (Cyber-themed UI)
  - Dashboard with scan statistics
  - Real-time scanning with radar animation
  - File upload scanner
  - Quarantine management system
  - Settings & theme customization
All screenshots are stored in the following LINK : (1. https://github.com/tanmay232003/CYBERSECURE-ANTI-VIRUS-SYSTEM/blob/main/Screenshot%202025-11-21%20013213.png

2.https://github.com/tanmay232003/CYBERSECURE-ANTI-VIRUS-SYSTEM/blob/main/Screenshot%202025-11-21%20013241.png

3.https://github.com/tanmay232003/CYBERSECURE-ANTI-VIRUS-SYSTEM/blob/main/Screenshot%202025-11-21%20013337.png

4.

       )

# CONCLUSION
-> This project showcases a practical implementation of antivirus fundamentals combined with modern web technologies. It is ideal for:
  -Cybersecurity beginners
  -Python/Flask learners
  -Academic projects
  -Portfolio demonstrations
