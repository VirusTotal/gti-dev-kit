```
Analyzing file hash: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0

Startinng Relationship Analysis for: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0

No cache file found. Fetching relationship data from API...
Fetching relationship data for file hash: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0
Relationship data cached at: cache\file_001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_relationships_cache.json

--- Relationship Summary for File Hash: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0 ---

> Related Threat Actors:
  - No related entities found.

> Campaigns:
  - No related entities found.

> Vulnerabilities:
  - No related entities found.

> Collections:
  - ID: 1653c4ff0e7219b9bc7b4a8686e69f68ff70d781fa38124a2661c85021e0f35b | Type: collection
  - ID: 4346d5e301db1cf6fd81e9806ee8e57c613c5aaa90f67291729605e485f9d3d5 | Type: collection
  - ID: b3d7bbf34d46240c63ece68fc436bb078782cfceb188b0a9c111225705c67434 | Type: collection
  - ID: 3af477a5cc229173d1c401f280f709c5cd4dff6e9a9cab706eeba21b9310506f | Type: collection
  - ID: 4a3947bbf3e6dfc923e557cbef146cbcb622a94ece022ffdc4603e184e76975f | Type: collection
  - ID: 7bde4f3e1ffd487dd5398b2ada4184a6790d8d35e008325957e141e91cd97c9f | Type: collection
  - ID: 9328ec850fd2a262e26f8abc9679362ab441aa94ba9eb11633a84f3d805f5deb | Type: collection
  - ID: 94c3d5196520b36b2b7393feeb970845997f3ef6bad41014fcdf68da66f66770 | Type: collection
  - ID: 970681a8527e5ccba24428abba9ee32fa30d48bf6c26bc326ffe6514d5594be4 | Type: collection
  - ID: b8909e72f434e8976b466142163f62d522fbcaa8cc4801f2d5da13fc25dcf772 | Type: collection
  - ID: c8818d7a043bfe3b9eef21163318ba9ba43661f55cb1296ab84aeff151591b83 | Type: collection
  - ID: b349f9f7e20b0f3b0446bbf6720cf040552840b00b4ea8a2e4f008f15e76e9a3 | Type: collection

> Malware Families:
  - ID: malware--f017ebbf-d60a-5769-8c24-1c568893be34 | Type: collection
  - ID: malware--fb36e9a8-29c3-5f37-8a50-d1f9c33624af | Type: collection
  - ID: malpedia_win_formbook | Type: collection

> Software Toolkits:
  - No related entities found.

> Reports:
  - ID: report--17-00009525 | Type: collection
  - ID: report--17-00010032 | Type: collection
  - ID: report--17-00010085 | Type: collection
  - ID: report--17-00011168 | Type: collection
  - ID: report--17-00011187 | Type: collection
  - ID: report--17-00011690 | Type: collection
  - ID: report--17-00011713 | Type: collection
  - ID: report--17-00012238 | Type: collection
  - ID: report--17-00012509 | Type: collection
  - ID: report--17-00014463 | Type: collection
  - ID: report--18-00001368 | Type: collection
  - ID: report--18-00001369 | Type: collection
  - ID: report--18-00001370 | Type: collection
  - ID: report--18-00001380 | Type: collection
  - ID: report--18-00002821 | Type: collection
  - ID: report--18-00005050 | Type: collection
  - ID: report--18-00005462 | Type: collection
  - ID: report--18-00005799 | Type: collection
  - ID: report--18-00005800 | Type: collection
  - ID: report--18-00005802 | Type: collection
========================================================================================================================

Startinng MITRE Analysis for: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0

No cache file found for 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0. Fetching MITRE data from API...
Successfully saved MITRE data for 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0 to cache file: cache\file_001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_mitre_data_cache.json

--- MITRE ATT&CK Data for File 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0 ---

Sandbox Name: CAPE Sandbox
  - Tactic: Discovery (TA0007)
    - Technique: System Information Discovery (T1082)
    - Technique: Virtualization/Sandbox Evasion (T1497)
  - Tactic: Defense Evasion (TA0005)
    - Technique: Virtualization/Sandbox Evasion (T1497)
    - Technique: Process Injection (T1055)
    - Technique: Obfuscated Files or Information (T1027)
    - Technique: Software Packing (T1027.002)
  - Tactic: Command and Control (TA0011)
    - Technique: Application Layer Protocol (T1071)
  - Tactic: Execution (TA0002)
    - Technique: Native API (T1106)
  - Tactic: Privilege Escalation (TA0004)
    - Technique: Process Injection (T1055)

Sandbox Name: Zenbox
  - Tactic: Execution (TA0002)
    - Technique: Shared Modules (T1129)
  - Tactic: Privilege Escalation (TA0004)
    - Technique: Process Injection (T1055)
  - Tactic: Defense Evasion (TA0005)
    - Technique: Process Injection (T1055)
    - Technique: Masquerading (T1036)
    - Technique: Virtualization/Sandbox Evasion (T1497)
    - Technique: Impair Defenses (T1562)
    - Technique: Disable or Modify Tools (T1562.001)
    - Technique: Obfuscated Files or Information (T1027)
    - Technique: Software Packing (T1027.002)
  - Tactic: Discovery (TA0007)
    - Technique: Virtualization/Sandbox Evasion (T1497)
    - Technique: Software Discovery (T1518)
    - Technique: Security Software Discovery (T1518.001)
    - Technique: Process Discovery (T1057)
    - Technique: Remote System Discovery (T1018)
    - Technique: System Information Discovery (T1082)
  - Tactic: Command and Control (TA0011)
    - Technique: Ingress Tool Transfer (T1105)
    - Technique: Non-Application Layer Protocol (T1095)
    - Technique: Application Layer Protocol (T1071)
========================================================================================================================

Startinng Sandbox Behavior Analysis for: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0

No cache file found for 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0. Fetching sandbox behaviours data from API...
Successfully saved sandbox behaviours data for 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0 to cache file: cache\file_001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_sandbox_behaviours_cache.json

--- Sandbox Behavior Analysis for File 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0 ---

Sandbox Name: C2AE
Behavior ID: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_C2AE
Command executions observed during the analysis of the file in the sandbox C2AE:
  - Command: %SAMPLEPATH%
---

Sandbox Name: CAPA
Behavior ID: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_CAPA
Command executions observed during the analysis of the file in the sandbox CAPA:
  No command executions found.

Sandbox Name: CAPE Sandbox
Behavior ID: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_CAPE Sandbox
Command executions observed during the analysis of the file in the sandbox CAPE Sandbox:
  - Command: "C:\Users\<USER>\Desktop\file.exe"
---

Sandbox Name: Lastline
Behavior ID: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_Lastline
Command executions observed during the analysis of the file in the sandbox Lastline:
  - Command: C:\Users\Elijah\AppData\Local\Temp\KI3OfSh6F2gSKKRV9HCiD.exe
  - Command: C:\Windows\Explorer.EXE
  - Command: C:\Windows\SysWOW64\raserver.exe
  - Command: /c del C:\Users\Elijah\AppData\Local\Temp\KI3OfSh6F2gSKKRV9HCiD.exe
---

Sandbox Name: Microsoft Sysinternals
Behavior ID: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_Microsoft Sysinternals
Command executions observed during the analysis of the file in the sandbox Microsoft Sysinternals:
  - Command: "%SAMPLEPATH%\001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0.exe" 
  - Command: "%SAMPLEPATH%\001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0.exe"
  - Command: C:\Windows\System32\wuapihost.exe -Embedding
  - Command: C:\Windows\system32\UI0Detect.exe
  - Command: "C:\Program Files\Google2148_471479055\bin\updater.exe" --update --system --enable-logging --vmodule=*/chrome/updater/*=2 /sessionid {0AE0BB96-9B06-4524-B8EC-5B2492B0EE0C}
---

Sandbox Name: Tencent HABO
Behavior ID: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_Tencent HABO
Command executions observed during the analysis of the file in the sandbox Tencent HABO:
  No command executions found.

Sandbox Name: VMRay
Behavior ID: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_VMRay
Command executions observed during the analysis of the file in the sandbox VMRay:
  - Command: "C:\Users\RDhJ0CNFevzX\Desktop\bom-01.exe"
  - Command: /c del "C:\Users\RDhJ0CNFevzX\Desktop\bom-01.exe"
  - Command: C:\Windows\Explorer.EXE
  - Command: "C:\Program Files (x86)\Jprwpylmx\9r_sncl_rt.exe"
  - Command: "C:\Program Files (x86)\Jprwpylmx\9r_sncl_rt.exe" 
  - Command: "C:\Users\RDhJ0CNFevzX\Desktop\bom-01.exe" 
  - Command: "C:\Windows\SysWOW64\cmd.exe"
---

Sandbox Name: VenusEye Sandbox
Behavior ID: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_VenusEye Sandbox
Command executions observed during the analysis of the file in the sandbox VenusEye Sandbox:
  - Command: %WINDIR%\system32\sppsvc.exe
  - Command: %WINDIR%\system32\wbem\wmiprvse.exe -Embedding
  - Command: %WINDIR%\system32\wbem\wmiprvse.exe -secured -Embedding
  - Command: taskhost.exe $(Arg0)
  - Command: taskhost.exe SYSTEM
---

Sandbox Name: VirusTotal Jujubox
Behavior ID: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_VirusTotal Jujubox
Command executions observed during the analysis of the file in the sandbox VirusTotal Jujubox:
  No command executions found.

Sandbox Name: VirusTotal Observer
Behavior ID: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0_VirusTotal Observer
Command executions observed during the analysis of the file in the sandbox VirusTotal Observer:
  No command executions found.
========================================================================================================================

Analysis completed for: 001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0
```