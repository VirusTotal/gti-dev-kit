```
Starting analysis for: 0078c8132fb99b4bccbb2e2429885a857d6a89534f74e23e6a12821abd2c3db2

Fetching File analysis report...
No cache file found for 0078c8132fb99b4bccbb2e2429885a857d6a89534f74e23e6a12821abd2c3db2. Fetching file report from API...
Successfully saved file report for 0078c8132fb99b4bccbb2e2429885a857d6a89534f74e23e6a12821abd2c3db2 to cache file: cache\file_0078c8132fb99b4bccbb2e2429885a857d6a89534f74e23e6a12821abd2c3db2_cache_file.json

--- File Threat Intelligence Report for 0078c8132fb99b4bccbb2e2429885a857d6a89534f74e23e6a12821abd2c3db2 ---
A deep link back to the full report in the GTI user interface: https://www.virustotal.com/gui/file/0078c8132fb99b4bccbb2e2429885a857d6a89534f74e23e6a12821abd2c3db2

Verdict: MALICIOUS
Malicious detections: 44

GTI Assessment:
  severity: {'value': 'SEVERITY_HIGH'}
  threat_score: {'value': 80}
  verdict: {'value': 'VERDICT_MALICIOUS'}
  contributing_factors: {'normalised_categories': ['ransomware'], 'gavs_detections': 3, 'gavs_categories': ['ransom']}
  description: This indicator is malicious (high severity) with high impact. It was detected by Google's spam and threat filtering engines, categorised as ransomware and categorised as ransomware. Analysts should prioritize investigation.

====== Full JSON Report ========
 {
  "data": {
    "id": "0078c8132fb99b4bccbb2e2429885a857d6a89534f74e23e6a12821abd2c3db2",
    "type": "file",
    "links": {
      "self": "https://www.virustotal.com/api/v3/files/0078c8132fb99b4bccbb2e2429885a857d6a89534f74e23e6a12821abd2c3db2"
    },
    "attributes": {
      "first_submission_date": 1747109144,
      "type_tags": [
        "executable",
        "windows",
        "win32",
        "pe",
        "peexe"
      ],
      "unique_sources": 1,
      "magic": "PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows",
      "threat_severity": {
        "version": 5,
        "threat_severity_level": "SEVERITY_HIGH",
        "threat_severity_data": {
          "popular_threat_category": "ransomware",
          "has_vulnerabilities": true,
          "num_gav_detections": 3
        },
        "last_analysis_date": "1747109219",
        "level_description": "Severity HIGH because it was considered ransomware. Other contributing factors were that it has known exploits and it could not be run in sandboxes."
      },
      "type_tag": "peexe",
      "last_modification_date": 1747713784,
      "last_submission_date": 1747109144,
      "sandbox_verdicts": {
        "C2AE": {
          "category": "undetected",
          "malware_classification": [
            "UNKNOWN_VERDICT"
          ],
          "sandbox_name": "C2AE"
        }
      },
      "authentihash": "51f0e2231c12ba010e1fedc0cf77fe02bc5f61e0ec66b52bdc410194f9eafdf2",
      "ssdeep": "49152:ieutLO9rb/TrvO90dL3BmAFd4A64nsfJJ2TIA5GNP1Jr4u/TgAPNdi9128qk1q4o:ieF+iIAEl1JPz212IhzL+Bzz3dw/Vkz",
      "size": 4385462,
      "total_votes": {
        "harmless": 0,
        "malicious": 0
      },
      "downloadable": true,
      "times_submitted": 1,
      "md5": "37ece581c10a7a88ee6c666b13807a03",
      "vhash": "0460d6655d55557575157az28!z",
      "names": [
        "/scratch/zoo/2025/05/13/37ece581c10a7a88ee6c666b13807a03"
      ],
      "last_analysis_results": {
        "Bkav": {
          "method": "blacklist",
          "engine_name": "Bkav",
          "engine_version": "2.0.0.1",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "W64.AIDetectMalware"
        },
        "Lionic": {
          "method": "blacklist",
          "engine_name": "Lionic",
          "engine_version": "8.16",
          "engine_update": "20250512",
          "category": "undetected",
          "result": null
        },
        "Elastic": {
          "method": "blacklist",
          "engine_name": "Elastic",
          "engine_version": "4.0.203",
          "engine_update": "20250505",
          "category": "malicious",
          "result": "malicious (high confidence)"
        },
        "MicroWorld-eScan": {
          "method": "blacklist",
          "engine_name": "MicroWorld-eScan",
          "engine_version": "14.0.409.0",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Trojan.Ransom.Hive.AF"
        },
        "CTX": {
          "method": "blacklist",
          "engine_name": "CTX",
          "engine_version": "2024.8.29.1",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "exe.ransomware.hive"
        },
        "CAT-QuickHeal": {
          "method": "blacklist",
          "engine_name": "CAT-QuickHeal",
          "engine_version": "22.00",
          "engine_update": "20250512",
          "category": "undetected",
          "result": null
        },
        "Skyhigh": {
          "method": "blacklist",
          "engine_name": "Skyhigh",
          "engine_version": "v2021.2.0+4045",
          "engine_update": "20250512",
          "category": "undetected",
          "result": null
        },
        "ALYac": {
          "method": "blacklist",
          "engine_name": "ALYac",
          "engine_version": "2.0.0.10",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Trojan.Ransom.Hive.AF"
        },
        "Malwarebytes": {
          "method": "blacklist",
          "engine_name": "Malwarebytes",
          "engine_version": "4.5.5.54",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Generic.Malware.AI.DDS"
        },
        "Zillya": {
          "method": "blacklist",
          "engine_name": "Zillya",
          "engine_version": "2.0.0.5358",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Worm.Recyl.Win32.92"
        },
        "Sangfor": {
          "method": "blacklist",
          "engine_name": "Sangfor",
          "engine_version": "2.22.3.0",
          "engine_update": "20250510",
          "category": "undetected",
          "result": null
        },
        "K7AntiVirus": {
          "method": "blacklist",
          "engine_name": "K7AntiVirus",
          "engine_version": "12.236.55730",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Trojan ( 0058d8291 )"
        },
        "Alibaba": {
          "method": "blacklist",
          "engine_name": "Alibaba",
          "engine_version": "0.3.0.5",
          "engine_update": "20190527",
          "category": "undetected",
          "result": null
        },
        "K7GW": {
          "method": "blacklist",
          "engine_name": "K7GW",
          "engine_version": "12.236.55731",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Trojan ( 0058d8291 )"
        },
        "CrowdStrike": {
          "method": "blacklist",
          "engine_name": "CrowdStrike",
          "engine_version": "1.0",
          "engine_update": "20231026",
          "category": "malicious",
          "result": "win/malicious_confidence_100% (D)"
        },
        "huorong": {
          "method": "blacklist",
          "engine_name": "huorong",
          "engine_version": "eb5b288:eb5b288:41b8ce2:41b8ce2",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Ransom/LockFile.fr"
        },
        "Baidu": {
          "method": "blacklist",
          "engine_name": "Baidu",
          "engine_version": "1.0.0.2",
          "engine_update": "20190318",
          "category": "undetected",
          "result": null
        },
        "VirIT": {
          "method": "blacklist",
          "engine_name": "VirIT",
          "engine_version": "9.5.952",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Trojan.Win64.Agent.HWS"
        },
        "Symantec": {
          "method": "blacklist",
          "engine_name": "Symantec",
          "engine_version": "1.22.0.0",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Trojan.Gen.MBT"
        },
        "tehtris": {
          "method": "blacklist",
          "engine_name": "tehtris",
          "engine_version": "v0.1.4",
          "engine_update": "20250513",
          "category": "undetected",
          "result": null
        },
        "ESET-NOD32": {
          "method": "blacklist",
          "engine_name": "ESET-NOD32",
          "engine_version": "31188",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "WinGo/Agent.EU"
        },
        "Cynet": {
          "method": "blacklist",
          "engine_name": "Cynet",
          "engine_version": "4.0.3.4",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Malicious (score: 99)"
        },
        "APEX": {
          "method": "blacklist",
          "engine_name": "APEX",
          "engine_version": "6.653",
          "engine_update": "20250510",
          "category": "malicious",
          "result": "Malicious"
        },
        "Paloalto": {
          "method": "blacklist",
          "engine_name": "Paloalto",
          "engine_version": "0.9.0.1003",
          "engine_update": "20250513",
          "category": "undetected",
          "result": null
        },
        "ClamAV": {
          "method": "blacklist",
          "engine_name": "ClamAV",
          "engine_version": "1.4.2.0",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Win.Ransomware.Generickdz-9940598-0"
        },
        "Kaspersky": {
          "method": "blacklist",
          "engine_name": "Kaspersky",
          "engine_version": "22.0.1.28",
          "engine_update": "20250513",
          "category": "undetected",
          "result": null
        },
        "BitDefender": {
          "method": "blacklist",
          "engine_name": "BitDefender",
          "engine_version": "7.2",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Trojan.Ransom.Hive.AF"
        },
        "NANO-Antivirus": {
          "method": "blacklist",
          "engine_name": "NANO-Antivirus",
          "engine_version": "1.0.170.26531",
          "engine_update": "20250513",
          "category": "undetected",
          "result": null
        },
        "SUPERAntiSpyware": {
          "method": "blacklist",
          "engine_name": "SUPERAntiSpyware",
          "engine_version": "5.6.0.1032",
          "engine_update": "20250512",
          "category": "undetected",
          "result": null
        },
        "Avast": {
          "method": "blacklist",
          "engine_name": "Avast",
          "engine_version": "23.9.8494.0",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Win64:MalwareX-gen [Ransom]"
        },
        "Tencent": {
          "method": "blacklist",
          "engine_name": "Tencent",
          "engine_version": "1.0.0.1",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Worm.Win64.Recyl.ha"
        },
        "Emsisoft": {
          "method": "blacklist",
          "engine_name": "Emsisoft",
          "engine_version": "2024.8.0.61147",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Trojan.Ransom.Hive.AF (B)"
        },
        "F-Secure": {
          "method": "blacklist",
          "engine_name": "F-Secure",
          "engine_version": "18.10.1547.307",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Heuristic.HEUR/AGEN.1319840"
        },
        "DrWeb": {
          "method": "blacklist",
          "engine_name": "DrWeb",
          "engine_version": "7.0.67.2170",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Trojan.Siggen17.18834"
        },
        "VIPRE": {
          "method": "blacklist",
          "engine_name": "VIPRE",
          "engine_version": "6.0.0.35",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Trojan.Ransom.Hive.AF"
        },
        "TrendMicro": {
          "method": "blacklist",
          "engine_name": "TrendMicro",
          "engine_version": "24.550.0.1002",
          "engine_update": "20250513",
          "category": "undetected",
          "result": null
        },
        "McAfeeD": {
          "method": "blacklist",
          "engine_name": "McAfeeD",
          "engine_version": "1.2.0.7977",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "ti!0078C8132FB9"
        },
        "Trapmine": {
          "method": "blacklist",
          "engine_name": "Trapmine",
          "engine_version": "4.0.4.0",
          "engine_update": "20250417",
          "category": "undetected",
          "result": null
        },
        "CMC": {
          "method": "blacklist",
          "engine_name": "CMC",
          "engine_version": "2.4.2022.1",
          "engine_update": "20250513",
          "category": "undetected",
          "result": null
        },
        "Sophos": {
          "method": "blacklist",
          "engine_name": "Sophos",
          "engine_version": "3.0.3.0",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Mal/Generic-S"
        },
        "Ikarus": {
          "method": "blacklist",
          "engine_name": "Ikarus",
          "engine_version": "6.3.30.0",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Trojan-Ransom.FileCrypter"
        },
        "GData": {
          "method": "blacklist",
          "engine_name": "GData",
          "engine_version": "GD:27.40304AVA:64.29184",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Win64.Virus.Gofing.A"
        },
        "Jiangmin": {
          "method": "blacklist",
          "engine_name": "Jiangmin",
          "engine_version": "16.0.100",
          "engine_update": "20250512",
          "category": "undetected",
          "result": null
        },
        "Webroot": {
          "method": "blacklist",
          "engine_name": "Webroot",
          "engine_version": "1.9.0.8",
          "engine_update": "20250227",
          "category": "undetected",
          "result": null
        },
        "Varist": {
          "method": "blacklist",
          "engine_name": "Varist",
          "engine_version": "6.6.1.3",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "W64/Gofing.A.gen!Eldorado"
        },
        "Avira": {
          "method": "blacklist",
          "engine_name": "Avira",
          "engine_version": "8.3.3.20",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "HEUR/AGEN.1319840"
        },
        "Antiy-AVL": {
          "method": "blacklist",
          "engine_name": "Antiy-AVL",
          "engine_version": "3.0",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Worm/Win32.Recyl"
        },
        "Kingsoft": {
          "method": "blacklist",
          "engine_name": "Kingsoft",
          "engine_version": "None",
          "engine_update": "20250512",
          "category": "undetected",
          "result": null
        },
        "Gridinsoft": {
          "method": "blacklist",
          "engine_name": "Gridinsoft",
          "engine_version": "1.0.216.174",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Ransom.Win64.Sabsik.oa!s1"
        },
        "Xcitium": {
          "method": "blacklist",
          "engine_name": "Xcitium",
          "engine_version": "37718",
          "engine_update": "20250510",
          "category": "undetected",
          "result": null
        },
        "Arcabit": {
          "method": "blacklist",
          "engine_name": "Arcabit",
          "engine_version": "2022.0.0.18",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Trojan.Ransom.Hive.AF"
        },
        "ViRobot": {
          "method": "blacklist",
          "engine_name": "ViRobot",
          "engine_version": "2014.3.20.0",
          "engine_update": "20250513",
          "category": "undetected",
          "result": null
        },
        "ZoneAlarm": {
          "method": "blacklist",
          "engine_name": "ZoneAlarm",
          "engine_version": "6.16-103870537",
          "engine_update": "20250513",
          "category": "undetected",
          "result": null
        },
        "Microsoft": {
          "method": "blacklist",
          "engine_name": "Microsoft",
          "engine_version": "1.1.25030.1",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Ransom:Win64/Hive!pz"
        },
        "Google": {
          "method": "blacklist",
          "engine_name": "Google",
          "engine_version": "1747704635",
          "engine_update": "20250520",
          "category": "malicious",
          "result": "Detected"
        },
        "AhnLab-V3": {
          "method": "blacklist",
          "engine_name": "AhnLab-V3",
          "engine_version": "3.27.2.10550",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Trojan/Win.Generic.R475417"
        },
        "Acronis": {
          "method": "blacklist",
          "engine_name": "Acronis",
          "engine_version": "1.2.0.121",
          "engine_update": "20240328",
          "category": "undetected",
          "result": null
        },
        "McAfee": {
          "method": "blacklist",
          "engine_name": "McAfee",
          "engine_version": "6.0.6.653",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "GenericRXAA-AA!37ECE581C10A"
        },
        "TACHYON": {
          "method": "blacklist",
          "engine_name": "TACHYON",
          "engine_version": "2025-05-13.01",
          "engine_update": "20250513",
          "category": "undetected",
          "result": null
        },
        "VBA32": {
          "method": "blacklist",
          "engine_name": "VBA32",
          "engine_version": "5.3.2",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Worm.Win64.Recyl"
        },
        "Cylance": {
          "method": "blacklist",
          "engine_name": "Cylance",
          "engine_version": "3.0.0.0",
          "engine_update": "20250424",
          "category": "undetected",
          "result": null
        },
        "Panda": {
          "method": "blacklist",
          "engine_name": "Panda",
          "engine_version": "4.6.4.2",
          "engine_update": "20250512",
          "category": "undetected",
          "result": null
        },
        "Zoner": {
          "method": "blacklist",
          "engine_name": "Zoner",
          "engine_version": "2.2.2.0",
          "engine_update": "20250513",
          "category": "undetected",
          "result": null
        },
        "TrendMicro-HouseCall": {
          "method": "blacklist",
          "engine_name": "TrendMicro-HouseCall",
          "engine_version": "24.550.0.1002",
          "engine_update": "20250513",
          "category": "undetected",
          "result": null
        },
        "Rising": {
          "method": "blacklist",
          "engine_name": "Rising",
          "engine_version": "25.0.0.28",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "Virus.Velocity!1.DB37 (CLASSIC)"
        },
        "Yandex": {
          "method": "blacklist",
          "engine_name": "Yandex",
          "engine_version": "5.5.2.24",
          "engine_update": "20250512",
          "category": "undetected",
          "result": null
        },
        "SentinelOne": {
          "method": "blacklist",
          "engine_name": "SentinelOne",
          "engine_version": "25.1.1.1",
          "engine_update": "20250114",
          "category": "malicious",
          "result": "Static AI - Suspicious PE"
        },
        "MaxSecure": {
          "method": "blacklist",
          "engine_name": "MaxSecure",
          "engine_version": "1.0.0.1",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Trojan.Malware.300983.susgen"
        },
        "Fortinet": {
          "method": "blacklist",
          "engine_name": "Fortinet",
          "engine_version": "7.0.30.0",
          "engine_update": "20250513",
          "category": "malicious",
          "result": "W64/Gofing.A!tr"
        },
        "AVG": {
          "method": "blacklist",
          "engine_name": "AVG",
          "engine_version": "23.9.8494.0",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "Win64:MalwareX-gen [Ransom]"
        },
        "DeepInstinct": {
          "method": "blacklist",
          "engine_name": "DeepInstinct",
          "engine_version": "5.0.0.8",
          "engine_update": "20250512",
          "category": "malicious",
          "result": "MALICIOUS"
        },
        "alibabacloud": {
          "method": "blacklist",
          "engine_name": "alibabacloud",
          "engine_version": "2.2.0",
          "engine_update": "20250321",
          "category": "undetected",
          "result": null
        },
        "google_safebrowsing": {
          "method": "blacklist",
          "engine_name": "google_safebrowsing",
          "engine_version": "1.0",
          "engine_update": "20250513",
          "category": "undetected",
          "result": null
        },
        "Trustlook": {
          "method": "blacklist",
          "engine_name": "Trustlook",
          "engine_version": "1.0",
          "engine_update": "20250513",
          "category": "type-unsupported",
          "result": null
        },
        "SymantecMobileInsight": {
          "method": "blacklist",
          "engine_name": "SymantecMobileInsight",
          "engine_version": "2.0",
          "engine_update": "20250124",
          "category": "type-unsupported",
          "result": null
        },
        "BitDefenderFalx": {
          "method": "blacklist",
          "engine_name": "BitDefenderFalx",
          "engine_version": "2.0.936",
          "engine_update": "20250416",
          "category": "type-unsupported",
          "result": null
        },
        "Avast-Mobile": {
          "method": "blacklist",
          "engine_name": "Avast-Mobile",
          "engine_version": "250512-00",
          "engine_update": "20250512",
          "category": "type-unsupported",
          "result": null
        }
      },
      "trid": [
        {
          "file_type": "Win64 Executable (generic)",
          "probability": 48.7
        },
        {
          "file_type": "Win16 NE executable (generic)",
          "probability": 23.3
        },
        {
          "file_type": "OS/2 Executable (generic)",
          "probability": 9.3
        },
        {
          "file_type": "Generic Win/DOS Executable",
          "probability": 9.2
        },
        {
          "file_type": "DOS Executable Generic",
          "probability": 9.2
        }
      ],
      "tlsh": "T156169D03FC9564A9C5E9F23089758392BA717858473127D33F64AABB2A737C41FB9390",
      "last_analysis_date": 1747109144,
      "last_analysis_stats": {
        "malicious": 44,
        "suspicious": 0,
        "undetected": 29,
        "harmless": 0,
        "timeout": 0,
        "confirmed-timeout": 0,
        "failure": 0,
        "type-unsupported": 4
      },
      "popular_threat_classification": {
        "popular_threat_category": [
          {
            "value": "ransomware",
            "count": 14
          },
          {
            "value": "trojan",
            "count": 14
          },
          {
            "value": "worm",
            "count": 4
          }
        ],
        "popular_threat_name": [
          {
            "value": "hive",
            "count": 8
          },
          {
            "value": "recyl",
            "count": 4
          },
          {
            "value": "gofing",
            "count": 3
          }
        ],
        "suggested_threat_label": "ransomware.hive/recyl"
      },
      "sha256": "0078c8132fb99b4bccbb2e2429885a857d6a89534f74e23e6a12821abd2c3db2",
      "available_tools": [
        "capa"
      ],
      "tags": [
        "peexe",
        "64bits",
        "overlay",
        "spreader"
      ],
      "type_description": "Win32 EXE",
      "type_extension": "exe",
      "exiftool": {
        "MIMEType": "application/octet-stream",
        "Subsystem": "Windows command line",
        "MachineType": "AMD AMD64",
        "TimeStamp": "0000:00:00 00:00:00",
        "FileType": "Win64 EXE",
        "PEType": "PE32+",
        "CodeSize": "1319424",
        "InitializedDataSize": "226816",
        "ImageFileCharacteristics": "Executable, Large address aware, No debug",
        "FileTypeExtension": "exe",
        "LinkerVersion": "3.0",
        "SubsystemVersion": "6.1",
        "EntryPoint": "0x63740",
        "OSVersion": "6.1",
        "ImageVersion": "1.0",
        "UninitializedDataSize": "0"
      },
      "reputation": 0,
      "detectiteasy": {
        "filetype": "PE64",
        "values": [
          {
            "version": "1.15.0-X.XX.X",
            "type": "Compiler",
            "name": "Go"
          }
        ]
      },
      "sha1": "33d915448f1bc6b8a479d160a73df38129a4ccb1",
      "pe_info": {
        "imphash": "c7269d59926fa4252270f407e4dab043",
        "machine_type": 34404,
        "entry_point": 407360,
        "overlay": {
          "chi2": 337719.78,
          "filetype": "unknown",
          "entropy": 6.341569423675537,
          "offset": 4305920,
          "md5": "ac286874584c8186a940cba87b190912",
          "size": 79542
        },
        "sections": [
          {
            "name": ".text",
            "chi2": 11400868.0,
            "virtual_address": 4096,
            "entropy": 6.21,
            "raw_size": 1319424,
            "flags": "rx",
            "virtual_size": 1319301,
            "md5": "1353d1d221ee35e4fb289453fca360a9"
          },
          {
            "name": ".rdata",
            "chi2": 49527204.0,
            "virtual_address": 1327104,
            "entropy": 5.19,
            "raw_size": 1340416,
            "flags": "r",
            "virtual_size": 1340104,
            "md5": "d8d3ac8434a7743cc7ddee02a56d561b"
          },
          {
            "name": ".data",
            "chi2": 10276661.0,
            "virtual_address": 2670592,
            "entropy": 5.25,
            "raw_size": 226816,
            "flags": "rw",
            "virtual_size": 610688,
            "md5": "60966e060d2d1e8ea0653867a76f9593"
          },
          {
            "name": "/4",
            "chi2": 28570.0,
            "virtual_address": 3284992,
            "entropy": 4.83,
            "raw_size": 512,
            "flags": "r",
            "virtual_size": 281,
            "md5": "28a3e9c96b9bb43e6541a26c8f68899b"
          },
          {
            "name": "/19",
            "chi2": 1297.96,
            "virtual_address": 3289088,
            "entropy": 8.0,
            "raw_size": 238080,
            "flags": "r",
            "virtual_size": 237739,
            "md5": "0c4d9159d1ec36b47b0dbfe7c6cdd157"
          },
          {
            "name": "/32",
            "chi2": 4531.84,
            "virtual_address": 3530752,
            "entropy": 7.94,
            "raw_size": 45568,
            "flags": "r",
            "virtual_size": 45085,
            "md5": "a7c58e4e47b73b2e20920a0fb1ca5b37"
          },
          {
            "name": "/46",
            "chi2": 107659.0,
            "virtual_address": 3579904,
            "entropy": 0.86,
            "raw_size": 512,
            "flags": "r",
            "virtual_size": 48,
            "md5": "40cca7c46fc713b4f088e5d440ca7931"
          },
          {
            "name": "/65",
            "chi2": 1957.07,
            "virtual_address": 3584000,
            "entropy": 8.0,
            "raw_size": 522752,
            "flags": "r",
            "virtual_size": 522571,
            "md5": "9b6336958241b6a8bee5ac4e1db6cd0e"
          },
          {
            "name": "/78",
            "chi2": 2048.77,
            "virtual_address": 4108288,
            "entropy": 7.99,
            "raw_size": 259584,
            "flags": "r",
            "virtual_size": 259466,
            "md5": "248f35cc14ef53fa84b8d8910d95ef91"
          },
          {
            "name": "/90",
            "chi2": 22914.31,
            "virtual_address": 4370432,
            "entropy": 7.81,
            "raw_size": 75264,
            "flags": "r",
            "virtual_size": 75163,
            "md5": "5bcb8fde317ecad65c5b5cfc6a3794ba"
          },
          {
            "name": ".idata",
            "chi2": 98295.49,
            "virtual_address": 4448256,
            "entropy": 3.58,
            "raw_size": 1536,
            "flags": "rw",
            "virtual_size": 1164,
            "md5": "a4339cbaf65731ed13368524ab7c4a35"
          },
          {
            "name": ".reloc",
            "chi2": 300355.28,
            "virtual_address": 4452352,
            "entropy": 5.45,
            "raw_size": 54784,
            "flags": "r",
            "virtual_size": 54564,
            "md5": "187f6f8c5b94f04a024e19466fd252f9"
          },
          {
            "name": ".symtab",
            "chi2": 3358283.5,
            "virtual_address": 4509696,
            "entropy": 5.31,
            "raw_size": 219136,
            "flags": "r",
            "virtual_size": 219116,
            "md5": "bbb9c1b7d4af9f5cb0c5852f662bbb8c"
          }
        ],
        "import_list": [
          {
            "library_name": "kernel32.dll",
            "imported_functions": [
              "AddVectoredExceptionHandler",
              "CloseHandle",
              "CreateEventA",
              "CreateFileA",
              "CreateIoCompletionPort",
              "CreateThread",
              "CreateWaitableTimerExW",
              "DuplicateHandle",
              "ExitProcess",
              "FreeEnvironmentStringsW",
              "GetConsoleMode",
              "GetEnvironmentStringsW",
              "GetProcAddress",
              "GetProcessAffinityMask",
              "GetQueuedCompletionStatusEx",
              "GetStdHandle",
              "GetSystemDirectoryA",
              "GetSystemInfo",
              "GetThreadContext",
              "LoadLibraryA",
              "LoadLibraryW",
              "PostQueuedCompletionStatus",
              "ResumeThread",
              "SetConsoleCtrlHandler",
              "SetErrorMode",
              "SetEvent",
              "SetProcessPriorityBoost",
              "SetThreadContext",
              "SetUnhandledExceptionFilter",
              "SetWaitableTimer",
              "Sleep",
              "SuspendThread",
              "SwitchToThread",
              "VirtualAlloc",
              "VirtualFree",
              "VirtualQuery",
              "WaitForMultipleObjects",
              "WaitForSingleObject",
              "WriteConsoleW",
              "WriteFile"
            ]
          }
        ]
      },
      "filecondis": {
        "dhash": "587c3e1c0e260b00",
        "raw_md5": "316cea3edc759c94fe20b6b2b88ce9dc"
      },
      "gti_assessment": {
        "severity": {
          "value": "SEVERITY_HIGH"
        },
        "threat_score": {
          "value": 80
        },
        "verdict": {
          "value": "VERDICT_MALICIOUS"
        },
        "contributing_factors": {
          "normalised_categories": [
            "ransomware"
          ],
          "gavs_detections": 3,
          "gavs_categories": [
            "ransom"
          ]
        },
        "description": "This indicator is malicious (high severity) with high impact. It was detected by Google's spam and threat filtering engines, categorised as ransomware and categorised as ransomware. Analysts should prioritize investigation."
      }
    }
  }
}
```