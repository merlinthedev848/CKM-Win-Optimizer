**CKM‑Win‑Optimizer**

CKM‑Win‑Optimizer is a comprehensive Windows maintenance and optimization script. It automates health checks, repairs, cleanup, debloat, updates, and audits — all with transparent logging and a clear summary dashboard.
The script is designed to be interactive, verbose, and user‑empowering: you see what’s happening, you can skip sections, and you get a neat summary first with the detailed log underneath.

**Features**
🛠️ **System Health & Repairs**
- Runs SFC and DISM to repair system files.
- Resets permissions and registry defaults (scoped to user profile and ProgramData).
- Cleans temporary files, caches, and prefetch data.
- Clears Windows Update cache safely.
- Empties the recycle bin.
- Disables non‑Microsoft startup items.
- Optimizes visual effects for performance.
- Sets power plan to High Performance.
- All successful actions increment the RepairCount in the summary.
🧹 **Debloat Windows Apps + Telemetry Removal**
- Curated removal list of unnecessary apps (Skype, 3D Viewer, OfficeHub, etc.).
- Interactive prompts let you choose whether to remove or keep each app.
- Protected apps (Store, Edge, Calculator, Teams, etc.) are skipped automatically.
- Disables telemetry via registry and services (DiagTrack, dmwappushservice, WerSvc, PcaSvc).
- Counters: RemovedCount, SkippedCount, ErrorCount updated automatically.
🔄 **Windows Updates**
- Uses PSWindowsUpdate if available.
- Falls back to USOClient if the module isn’t present.
- Applies all available OS updates.
- Counters: UpdateCount increments for each update applied.
📦 **Driver & Software Auto Update**
- Scans and refreshes drivers using pnputil.
- Updates installed apps via Winget.
- Logs whether updates were applied or skipped.
- Counters: UpdateCount, SkippedCount, ErrorCount updated accordingly.
📋 **Software Audit (x64 + x86)**
- Enumerates installed programs from both 64‑bit and 32‑bit registry hives.
- Flags apps unused for more than 6 months.
- Interactive prompts let you remove or keep flagged software.
- Optional AutoRemoveUnused switch removes old apps without prompting.
- Counters: AuditCount, RemovedCount, SkippedCount, ErrorCount updated automatically.
🔐 **Security Scans**
- Updates Windows Defender signatures.
- Runs a quick scan for malware.
- Logs results and increments counters.
💾 **Backup & Audit**
- Backs up user data to a safe location.
- Analyzes event logs for warnings/errors.
- Audits installed software for compliance.
- Counters: BackupStatus, AuditCount updated.
📊 **Logging & Summary**
- All actions logged to a buffer file during runtime.
- At completion, the script writes a summary first (Repairs, Removals, Skips, Errors, Updates, Backup, Audit).
- Full transcript appended under Enhanced Log.
- Interactive skip option: press Spacebar + Enter to skip a section, or just Enter to run it.

-------------------

⚙️ **Usage**
🖥️ Prerequisites
- Windows 10 or Windows 11.
- Run PowerShell as Administrator (right‑click → Run as Administrator).
- Internet connection (needed for updates, Winget, and Defender scans).
- Optional: Install the PSWindowsUpdate module for richer update handling.

--------------------

🧑‍🎓 **Novice User Instructions**
- Click on the green Code button and download ZIP.
- Copy the directory inside the ZIP file to your desktop.
- Right‑click on Run‑CKMWinFix.bat and select Run/Open as Administrator.
- When the script starts, you’ll see sections announced clearly (e.g. “=== Debloat Windows ===”).
- For each section, you can:
- Press Enter → run the section normally.
- Press Spacebar + Enter → skip the section.
- When prompted about removing apps or software:
- Type Y → remove it.
- Type N → keep it.
- Don’t worry: essential apps are protected and cannot be removed.
- At the end, you’ll see:
- A summary dashboard (Repairs, Removals, Skips, Errors, Updates, Backup, Audit).
- The full transcript underneath (Enhanced Log).
- The log file is saved automatically in the Logs folder next to the script.

🛡️ **Safety Notes**
- The script only touches safe, curated targets — no critical system apps are removed.
- All actions are logged with timestamps for transparency.
- If something fails, it’s recorded in the log and counted in the summary.
- You remain in control: nothing is removed or changed without your confirmation.

🧑‍💻 **Developer / Expert Mode**
Advanced User Instructions
▶️ How to Run
- Download the script (CKMWinFix.ps1) from this repository.
- Place it in a folder of your choice (e.g. C:\CKMWinOptimizer).
- Open PowerShell as Administrator.
- Navigate to the folder:
```
cd C:\CKMWinOptimizer
```
- Run the script directly:
```
.\CKMWinFix.ps1
```

🔧 **Advanced Options**
- Use the -AutoRemoveUnused switch with Audit-InstalledSoftware to remove unused apps without prompts.
- Modify $Global:EnableDebloat to toggle debloat functionality.
- Wrap sections in Invoke-Section for interactive skip control.
- Review logs in Logs\HealthCheckLog_*.txt for detailed diagnostics.
