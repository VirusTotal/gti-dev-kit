```
Starting analysis for: 8.8.8.8

Fetching IP analysis report...
No cache file found for 8.8.8.8. Fetching IP report from API...
Successfully saved IP report for 8.8.8.8 to cache file: cache\ip_8.8.8.8_cache_file.json

--- IP Address Threat Intelligence Report for 8.8.8.8 ---
A deep link back to the full report in the GTI user interface: https://www.virustotal.com/gui/ip-address/8.8.8.8

Verdict: CLEAN

Location Information:
Country: US
ASN: 15169
Network: 8.8.8.0/24

GTI Assessment:
  verdict: {'value': 'VERDICT_BENIGN'}
  contributing_factors: {'malicious_sandbox_verdict': False, 'mandiant_association_report': True, 'gti_confidence_score': 0, 'mandiant_confidence_score': 0, 'normalised_categories': ['phishing', 'infostealer', 'malware', 'control-server', 'phishing', 'malware'], 'pervasive_indicator': True, 'mandiant_analyst_benign': True, 'google_malware_analysis': True}
  severity: {'value': 'SEVERITY_NONE'}
  threat_score: {'value': 0}
  description: This indicator was determined as benign by a Mandiant analyst and likely poses no threat.

====== Full JSON Report ========
 {
  "data": {
    "id": "8.8.8.8",
    "type": "ip_address",
    "links": {
      "self": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
    },
    "attributes": {
      "country": "US",
      "last_https_certificate_date": 1754552889,
      "asn": 15169,
      "last_analysis_results": {
        "Acronis": {
          "method": "blacklist",
          "engine_name": "Acronis",
          "category": "harmless",
          "result": "clean"
        },
        "0xSI_f33d": {
          "method": "blacklist",
          "engine_name": "0xSI_f33d",
          "category": "undetected",
          "result": "unrated"
        },
        "Abusix": {
          "method": "blacklist",
          "engine_name": "Abusix",
          "category": "harmless",
          "result": "clean"
        },
        "ADMINUSLabs": {
          "method": "blacklist",
          "engine_name": "ADMINUSLabs",
          "category": "harmless",
          "result": "clean"
        },
        "Axur": {
          "method": "blacklist",
          "engine_name": "Axur",
          "category": "undetected",
          "result": "unrated"
        },
        "Criminal IP": {
          "method": "blacklist",
          "engine_name": "Criminal IP",
          "category": "harmless",
          "result": "clean"
        },
        "AILabs (MONITORAPP)": {
          "method": "blacklist",
          "engine_name": "AILabs (MONITORAPP)",
          "category": "harmless",
          "result": "clean"
        },
        "AlienVault": {
          "method": "blacklist",
          "engine_name": "AlienVault",
          "category": "harmless",
          "result": "clean"
        },
        "alphaMountain.ai": {
          "method": "blacklist",
          "engine_name": "alphaMountain.ai",
          "category": "undetected",
          "result": "unrated"
        },
        "AlphaSOC": {
          "method": "blacklist",
          "engine_name": "AlphaSOC",
          "category": "undetected",
          "result": "unrated"
        },
        "Antiy-AVL": {
          "method": "blacklist",
          "engine_name": "Antiy-AVL",
          "category": "harmless",
          "result": "clean"
        },
        "ArcSight Threat Intelligence": {
          "method": "blacklist",
          "engine_name": "ArcSight Threat Intelligence",
          "category": "undetected",
          "result": "unrated"
        },
        "AutoShun": {
          "method": "blacklist",
          "engine_name": "AutoShun",
          "category": "undetected",
          "result": "unrated"
        },
        "benkow.cc": {
          "method": "blacklist",
          "engine_name": "benkow.cc",
          "category": "harmless",
          "result": "clean"
        },
        "Bfore.Ai PreCrime": {
          "method": "blacklist",
          "engine_name": "Bfore.Ai PreCrime",
          "category": "undetected",
          "result": "unrated"
        },
        "BitDefender": {
          "method": "blacklist",
          "engine_name": "BitDefender",
          "category": "harmless",
          "result": "clean"
        },
        "Bkav": {
          "method": "blacklist",
          "engine_name": "Bkav",
          "category": "undetected",
          "result": "unrated"
        },
        "Blueliv": {
          "method": "blacklist",
          "engine_name": "Blueliv",
          "category": "harmless",
          "result": "clean"
        },
        "Certego": {
          "method": "blacklist",
          "engine_name": "Certego",
          "category": "harmless",
          "result": "clean"
        },
        "Chong Lua Dao": {
          "method": "blacklist",
          "engine_name": "Chong Lua Dao",
          "category": "harmless",
          "result": "clean"
        },
        "CINS Army": {
          "method": "blacklist",
          "engine_name": "CINS Army",
          "category": "harmless",
          "result": "clean"
        },
        "Cluster25": {
          "method": "blacklist",
          "engine_name": "Cluster25",
          "category": "undetected",
          "result": "unrated"
        },
        "CRDF": {
          "method": "blacklist",
          "engine_name": "CRDF",
          "category": "harmless",
          "result": "clean"
        },
        "CSIS Security Group": {
          "method": "blacklist",
          "engine_name": "CSIS Security Group",
          "category": "undetected",
          "result": "unrated"
        },
        "Snort IP sample list": {
          "method": "blacklist",
          "engine_name": "Snort IP sample list",
          "category": "harmless",
          "result": "clean"
        },
        "CMC Threat Intelligence": {
          "method": "blacklist",
          "engine_name": "CMC Threat Intelligence",
          "category": "harmless",
          "result": "clean"
        },
        "Cyan": {
          "method": "blacklist",
          "engine_name": "Cyan",
          "category": "undetected",
          "result": "unrated"
        },
        "Cyble": {
          "method": "blacklist",
          "engine_name": "Cyble",
          "category": "harmless",
          "result": "clean"
        },
        "CyRadar": {
          "method": "blacklist",
          "engine_name": "CyRadar",
          "category": "harmless",
          "result": "clean"
        },
        "DNS8": {
          "method": "blacklist",
          "engine_name": "DNS8",
          "category": "harmless",
          "result": "clean"
        },
        "Dr.Web": {
          "method": "blacklist",
          "engine_name": "Dr.Web",
          "category": "harmless",
          "result": "clean"
        },
        "Ermes": {
          "method": "blacklist",
          "engine_name": "Ermes",
          "category": "undetected",
          "result": "unrated"
        },
        "ESET": {
          "method": "blacklist",
          "engine_name": "ESET",
          "category": "harmless",
          "result": "clean"
        },
        "ESTsecurity": {
          "method": "blacklist",
          "engine_name": "ESTsecurity",
          "category": "harmless",
          "result": "clean"
        },
        "EmergingThreats": {
          "method": "blacklist",
          "engine_name": "EmergingThreats",
          "category": "harmless",
          "result": "clean"
        },
        "Emsisoft": {
          "method": "blacklist",
          "engine_name": "Emsisoft",
          "category": "harmless",
          "result": "clean"
        },
        "Forcepoint ThreatSeeker": {
          "method": "blacklist",
          "engine_name": "Forcepoint ThreatSeeker",
          "category": "harmless",
          "result": "clean"
        },
        "Fortinet": {
          "method": "blacklist",
          "engine_name": "Fortinet",
          "category": "harmless",
          "result": "clean"
        },
        "G-Data": {
          "method": "blacklist",
          "engine_name": "G-Data",
          "category": "harmless",
          "result": "clean"
        },
        "GCP Abuse Intelligence": {
          "method": "blacklist",
          "engine_name": "GCP Abuse Intelligence",
          "category": "undetected",
          "result": "unrated"
        },
        "Google Safebrowsing": {
          "method": "blacklist",
          "engine_name": "Google Safebrowsing",
          "category": "harmless",
          "result": "clean"
        },
        "GreenSnow": {
          "method": "blacklist",
          "engine_name": "GreenSnow",
          "category": "harmless",
          "result": "clean"
        },
        "Gridinsoft": {
          "method": "blacklist",
          "engine_name": "Gridinsoft",
          "category": "undetected",
          "result": "unrated"
        },
        "Heimdal Security": {
          "method": "blacklist",
          "engine_name": "Heimdal Security",
          "category": "harmless",
          "result": "clean"
        },
        "Hunt.io Intelligence": {
          "method": "blacklist",
          "engine_name": "Hunt.io Intelligence",
          "category": "undetected",
          "result": "unrated"
        },
        "IPsum": {
          "method": "blacklist",
          "engine_name": "IPsum",
          "category": "harmless",
          "result": "clean"
        },
        "Juniper Networks": {
          "method": "blacklist",
          "engine_name": "Juniper Networks",
          "category": "harmless",
          "result": "clean"
        },
        "Kaspersky": {
          "method": "blacklist",
          "engine_name": "Kaspersky",
          "category": "undetected",
          "result": "unrated"
        },
        "Lionic": {
          "method": "blacklist",
          "engine_name": "Lionic",
          "category": "harmless",
          "result": "clean"
        },
        "Lumu": {
          "method": "blacklist",
          "engine_name": "Lumu",
          "category": "undetected",
          "result": "unrated"
        },
        "MalwarePatrol": {
          "method": "blacklist",
          "engine_name": "MalwarePatrol",
          "category": "harmless",
          "result": "clean"
        },
        "MalwareURL": {
          "method": "blacklist",
          "engine_name": "MalwareURL",
          "category": "undetected",
          "result": "unrated"
        },
        "Malwared": {
          "method": "blacklist",
          "engine_name": "Malwared",
          "category": "harmless",
          "result": "clean"
        },
        "Mimecast": {
          "method": "blacklist",
          "engine_name": "Mimecast",
          "category": "undetected",
          "result": "unrated"
        },
        "Netcraft": {
          "method": "blacklist",
          "engine_name": "Netcraft",
          "category": "undetected",
          "result": "unrated"
        },
        "OpenPhish": {
          "method": "blacklist",
          "engine_name": "OpenPhish",
          "category": "harmless",
          "result": "clean"
        },
        "Phishing Database": {
          "method": "blacklist",
          "engine_name": "Phishing Database",
          "category": "harmless",
          "result": "clean"
        },
        "PhishFort": {
          "method": "blacklist",
          "engine_name": "PhishFort",
          "category": "undetected",
          "result": "unrated"
        },
        "PhishLabs": {
          "method": "blacklist",
          "engine_name": "PhishLabs",
          "category": "undetected",
          "result": "unrated"
        },
        "Phishtank": {
          "method": "blacklist",
          "engine_name": "Phishtank",
          "category": "harmless",
          "result": "clean"
        },
        "PREBYTES": {
          "method": "blacklist",
          "engine_name": "PREBYTES",
          "category": "harmless",
          "result": "clean"
        },
        "PrecisionSec": {
          "method": "blacklist",
          "engine_name": "PrecisionSec",
          "category": "undetected",
          "result": "unrated"
        },
        "Quick Heal": {
          "method": "blacklist",
          "engine_name": "Quick Heal",
          "category": "harmless",
          "result": "clean"
        },
        "Quttera": {
          "method": "blacklist",
          "engine_name": "Quttera",
          "category": "harmless",
          "result": "clean"
        },
        "SafeToOpen": {
          "method": "blacklist",
          "engine_name": "SafeToOpen",
          "category": "undetected",
          "result": "unrated"
        },
        "Sansec eComscan": {
          "method": "blacklist",
          "engine_name": "Sansec eComscan",
          "category": "undetected",
          "result": "unrated"
        },
        "Scantitan": {
          "method": "blacklist",
          "engine_name": "Scantitan",
          "category": "harmless",
          "result": "clean"
        },
        "SCUMWARE.org": {
          "method": "blacklist",
          "engine_name": "SCUMWARE.org",
          "category": "harmless",
          "result": "clean"
        },
        "Seclookup": {
          "method": "blacklist",
          "engine_name": "Seclookup",
          "category": "harmless",
          "result": "clean"
        },
        "SecureBrain": {
          "method": "blacklist",
          "engine_name": "SecureBrain",
          "category": "undetected",
          "result": "unrated"
        },
        "SOCRadar": {
          "method": "blacklist",
          "engine_name": "SOCRadar",
          "category": "harmless",
          "result": "clean"
        },
        "Sophos": {
          "method": "blacklist",
          "engine_name": "Sophos",
          "category": "harmless",
          "result": "clean"
        },
        "Spam404": {
          "method": "blacklist",
          "engine_name": "Spam404",
          "category": "harmless",
          "result": "clean"
        },
        "StopForumSpam": {
          "method": "blacklist",
          "engine_name": "StopForumSpam",
          "category": "harmless",
          "result": "clean"
        },
        "Sucuri SiteCheck": {
          "method": "blacklist",
          "engine_name": "Sucuri SiteCheck",
          "category": "harmless",
          "result": "clean"
        },
        "ThreatHive": {
          "method": "blacklist",
          "engine_name": "ThreatHive",
          "category": "harmless",
          "result": "clean"
        },
        "Threatsourcing": {
          "method": "blacklist",
          "engine_name": "Threatsourcing",
          "category": "harmless",
          "result": "clean"
        },
        "Trustwave": {
          "method": "blacklist",
          "engine_name": "Trustwave",
          "category": "undetected",
          "result": "unrated"
        },
        "Underworld": {
          "method": "blacklist",
          "engine_name": "Underworld",
          "category": "undetected",
          "result": "unrated"
        },
        "URLhaus": {
          "method": "blacklist",
          "engine_name": "URLhaus",
          "category": "harmless",
          "result": "clean"
        },
        "URLQuery": {
          "method": "blacklist",
          "engine_name": "URLQuery",
          "category": "undetected",
          "result": "unrated"
        },
        "Viettel Threat Intelligence": {
          "method": "blacklist",
          "engine_name": "Viettel Threat Intelligence",
          "category": "harmless",
          "result": "clean"
        },
        "VIPRE": {
          "method": "blacklist",
          "engine_name": "VIPRE",
          "category": "undetected",
          "result": "unrated"
        },
        "VX Vault": {
          "method": "blacklist",
          "engine_name": "VX Vault",
          "category": "harmless",
          "result": "clean"
        },
        "ViriBack": {
          "method": "blacklist",
          "engine_name": "ViriBack",
          "category": "harmless",
          "result": "clean"
        },
        "Webroot": {
          "method": "blacklist",
          "engine_name": "Webroot",
          "category": "harmless",
          "result": "clean"
        },
        "Yandex Safebrowsing": {
          "method": "blacklist",
          "engine_name": "Yandex Safebrowsing",
          "category": "harmless",
          "result": "clean"
        },
        "ZeroCERT": {
          "method": "blacklist",
          "engine_name": "ZeroCERT",
          "category": "harmless",
          "result": "clean"
        },
        "desenmascara.me": {
          "method": "blacklist",
          "engine_name": "desenmascara.me",
          "category": "harmless",
          "result": "clean"
        },
        "malwares.com URL checker": {
          "method": "blacklist",
          "engine_name": "malwares.com URL checker",
          "category": "harmless",
          "result": "clean"
        },
        "securolytics": {
          "method": "blacklist",
          "engine_name": "securolytics",
          "category": "harmless",
          "result": "clean"
        },
        "Xcitium Verdict Cloud": {
          "method": "blacklist",
          "engine_name": "Xcitium Verdict Cloud",
          "category": "undetected",
          "result": "unrated"
        },
        "zvelo": {
          "method": "blacklist",
          "engine_name": "zvelo",
          "category": "undetected",
          "result": "unrated"
        },
        "ZeroFox": {
          "method": "blacklist",
          "engine_name": "ZeroFox",
          "category": "undetected",
          "result": "unrated"
        }
      },
      "as_owner": "GOOGLE",
      "rdap": {
        "object_class_name": "ip network",
        "handle": "NET-8-8-8-0-2",
        "start_address": "8.8.8.0",
        "end_address": "8.8.8.255",
        "ip_version": "v4",
        "name": "GOGL",
        "type": "DIRECT ALLOCATION",
        "parent_handle": "NET-8-0-0-0-0",
        "status": [
          "active"
        ],
        "links": [
          {
            "href": "https://rdap.arin.net/registry/ip/8.8.8.0",
            "rel": "self",
            "type": "application/rdap+json",
            "value": "https://rdap.arin.net/registry/ip/8.8.8.8",
            "title": "",
            "media": "",
            "href_lang": []
          },
          {
            "href": "https://whois.arin.net/rest/net/NET-8-8-8-0-2",
            "rel": "alternate",
            "type": "application/xml",
            "value": "https://rdap.arin.net/registry/ip/8.8.8.8",
            "title": "",
            "media": "",
            "href_lang": []
          }
        ],
        "notices": [
          {
            "title": "Terms of Service",
            "description": [
              "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use"
            ],
            "links": [
              {
                "href": "https://www.arin.net/resources/registry/whois/tou/",
                "rel": "terms-of-service",
                "type": "text/html",
                "value": "https://rdap.arin.net/registry/ip/8.8.8.8",
                "title": "",
                "media": "",
                "href_lang": []
              }
            ],
            "type": ""
          },
          {
            "title": "Whois Inaccuracy Reporting",
            "description": [
              "If you see inaccuracies in the results, please visit: "
            ],
            "links": [
              {
                "href": "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/",
                "rel": "inaccuracy-report",
                "type": "text/html",
                "value": "https://rdap.arin.net/registry/ip/8.8.8.8",
                "title": "",
                "media": "",
                "href_lang": []
              }
            ],
            "type": ""
          },
          {
            "title": "Copyright Notice",
            "description": [
              "Copyright 1997-2025, American Registry for Internet Numbers, Ltd."
            ],
            "links": [],
            "type": ""
          }
        ],
        "events": [
          {
            "event_action": "last changed",
            "event_date": "2023-12-28T17:24:56-05:00",
            "event_actor": "",
            "links": []
          },
          {
            "event_action": "registration",
            "event_date": "2023-12-28T17:24:33-05:00",
            "event_actor": "",
            "links": []
          }
        ],
        "rdap_conformance": [
          "nro_rdap_profile_0",
          "rdap_level_0",
          "cidr0",
          "arin_originas0"
        ],
        "entities": [
          {
            "object_class_name": "entity",
            "handle": "GOGL",
            "vcard_array": [
              {
                "name": "version",
                "type": "text",
                "values": [
                  "4.0"
                ],
                "parameters": {}
              },
              {
                "name": "fn",
                "type": "text",
                "values": [
                  "Google LLC"
                ],
                "parameters": {}
              },
              {
                "name": "adr",
                "parameters": {
                  "label": [
                    "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"
                  ]
                },
                "type": "text",
                "values": [
                  "",
                  "",
                  "",
                  "",
                  "",
                  "",
                  ""
                ]
              },
              {
                "name": "kind",
                "type": "text",
                "values": [
                  "org"
                ],
                "parameters": {}
              }
            ],
            "roles": [
              "registrant"
            ],
            "entities": [
              {
                "object_class_name": "entity",
                "handle": "ABUSE5250-ARIN",
                "vcard_array": [
                  {
                    "name": "version",
                    "type": "text",
                    "values": [
                      "4.0"
                    ],
                    "parameters": {}
                  },
                  {
                    "name": "adr",
                    "parameters": {
                      "label": [
                        "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"
                      ]
                    },
                    "type": "text",
                    "values": [
                      "",
                      "",
                      "",
                      "",
                      "",
                      "",
                      ""
                    ]
                  },
                  {
                    "name": "fn",
                    "type": "text",
                    "values": [
                      "Abuse"
                    ],
                    "parameters": {}
                  },
                  {
                    "name": "org",
                    "type": "text",
                    "values": [
                      "Abuse"
                    ],
                    "parameters": {}
                  },
                  {
                    "name": "kind",
                    "type": "text",
                    "values": [
                      "group"
                    ],
                    "parameters": {}
                  },
                  {
                    "name": "email",
                    "type": "text",
                    "values": [
                      "network-abuse@google.com"
                    ],
                    "parameters": {}
                  },
                  {
                    "name": "tel",
                    "parameters": {
                      "type": [
                        "work",
                        "voice"
                      ]
                    },
                    "type": "text",
                    "values": [
                      "+1-650-253-0000"
                    ]
                  }
                ],
                "roles": [
                  "abuse"
                ],
                "remarks": [
                  {
                    "title": "Registration Comments",
                    "description": [
                      "Please note that the recommended way to file abuse complaints are located in the following links.",
                      "",
                      "To report abuse and illegal activity: https://www.google.com/contact/",
                      "",
                      "For legal requests: http://support.google.com/legal ",
                      "",
                      "Regards,",
                      "The Google Team"
                    ],
                    "links": [],
                    "type": ""
                  }
                ],
                "links": [
                  {
                    "href": "https://rdap.arin.net/registry/entity/ABUSE5250-ARIN",
                    "rel": "self",
                    "type": "application/rdap+json",
                    "value": "https://rdap.arin.net/registry/ip/8.8.8.8",
                    "title": "",
                    "media": "",
                    "href_lang": []
                  },
                  {
                    "href": "https://whois.arin.net/rest/poc/ABUSE5250-ARIN",
                    "rel": "alternate",
                    "type": "application/xml",
                    "value": "https://rdap.arin.net/registry/ip/8.8.8.8",
                    "title": "",
                    "media": "",
                    "href_lang": []
                  }
                ],
                "events": [
                  {
                    "event_action": "last changed",
                    "event_date": "2024-08-01T17:54:23-04:00",
                    "event_actor": "",
                    "links": []
                  },
                  {
                    "event_action": "registration",
                    "event_date": "2015-11-06T15:36:35-05:00",
                    "event_actor": "",
                    "links": []
                  }
                ],
                "status": [
                  "validated"
                ],
                "port43": "whois.arin.net",
                "public_ids": [],
                "entities": [],
                "as_event_actor": [],
                "networks": [],
                "autnums": [],
                "url": "",
                "lang": "",
                "rdap_conformance": []
              },
              {
                "object_class_name": "entity",
                "handle": "ZG39-ARIN",
                "vcard_array": [
                  {
                    "name": "version",
                    "type": "text",
                    "values": [
                      "4.0"
                    ],
                    "parameters": {}
                  },
                  {
                    "name": "adr",
                    "parameters": {
                      "label": [
                        "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States"
                      ]
                    },
                    "type": "text",
                    "values": [
                      "",
                      "",
                      "",
                      "",
                      "",
                      "",
                      ""
                    ]
                  },
                  {
                    "name": "fn",
                    "type": "text",
                    "values": [
                      "Google LLC"
                    ],
                    "parameters": {}
                  },
                  {
                    "name": "org",
                    "type": "text",
                    "values": [
                      "Google LLC"
                    ],
                    "parameters": {}
                  },
                  {
                    "name": "kind",
                    "type": "text",
                    "values": [
                      "group"
                    ],
                    "parameters": {}
                  },
                  {
                    "name": "email",
                    "type": "text",
                    "values": [
                      "arin-contact@google.com"
                    ],
                    "parameters": {}
                  },
                  {
                    "name": "tel",
                    "parameters": {
                      "type": [
                        "work",
                        "voice"
                      ]
                    },
                    "type": "text",
                    "values": [
                      "+1-650-253-0000"
                    ]
                  }
                ],
                "roles": [
                  "administrative",
                  "technical"
                ],
                "links": [
                  {
                    "href": "https://rdap.arin.net/registry/entity/ZG39-ARIN",
                    "rel": "self",
                    "type": "application/rdap+json",
                    "value": "https://rdap.arin.net/registry/ip/8.8.8.8",
                    "title": "",
                    "media": "",
                    "href_lang": []
                  },
                  {
                    "href": "https://whois.arin.net/rest/poc/ZG39-ARIN",
                    "rel": "alternate",
                    "type": "application/xml",
                    "value": "https://rdap.arin.net/registry/ip/8.8.8.8",
                    "title": "",
                    "media": "",
                    "href_lang": []
                  }
                ],
                "events": [
                  {
                    "event_action": "last changed",
                    "event_date": "2024-11-11T04:27:09-05:00",
                    "event_actor": "",
                    "links": []
                  },
                  {
                    "event_action": "registration",
                    "event_date": "2000-11-30T13:54:08-05:00",
                    "event_actor": "",
                    "links": []
                  }
                ],
                "status": [
                  "validated"
                ],
                "port43": "whois.arin.net",
                "public_ids": [],
                "entities": [],
                "remarks": [],
                "as_event_actor": [],
                "networks": [],
                "autnums": [],
                "url": "",
                "lang": "",
                "rdap_conformance": []
              }
            ],
            "remarks": [
              {
                "title": "Registration Comments",
                "description": [
                  "Please note that the recommended way to file abuse complaints are located in the following links. ",
                  "",
                  "To report abuse and illegal activity: https://www.google.com/contact/",
                  "",
                  "For legal requests: http://support.google.com/legal ",
                  "",
                  "Regards, ",
                  "The Google Team"
                ],
                "links": [],
                "type": ""
              }
            ],
            "links": [
              {
                "href": "https://rdap.arin.net/registry/entity/GOGL",
                "rel": "self",
                "type": "application/rdap+json",
                "value": "https://rdap.arin.net/registry/ip/8.8.8.8",
                "title": "",
                "media": "",
                "href_lang": []
              },
              {
                "href": "https://whois.arin.net/rest/org/GOGL",
                "rel": "alternate",
                "type": "application/xml",
                "value": "https://rdap.arin.net/registry/ip/8.8.8.8",
                "title": "",
                "media": "",
                "href_lang": []
              }
            ],
            "events": [
              {
                "event_action": "last changed",
                "event_date": "2019-10-31T15:45:45-04:00",
                "event_actor": "",
                "links": []
              },
              {
                "event_action": "registration",
                "event_date": "2000-03-30T00:00:00-05:00",
                "event_actor": "",
                "links": []
              }
            ],
            "port43": "whois.arin.net",
            "public_ids": [],
            "as_event_actor": [],
            "status": [],
            "networks": [],
            "autnums": [],
            "url": "",
            "lang": "",
            "rdap_conformance": []
          }
        ],
        "port43": "whois.arin.net",
        "cidr0_cidrs": [
          {
            "v4prefix": "8.8.8.0",
            "length": 24,
            "v6prefix": ""
          }
        ],
        "country": "",
        "arin_originas0_originautnums": [],
        "remarks": []
      },
      "last_analysis_date": 1754552878,
      "last_seen_itw_date": 1754525736,
      "continent": "NA",
      "last_https_certificate": {
        "cert_signature": {
          "signature_algorithm": "sha256RSA",
          "signature": "720fe29310663113889e890cb53bfc1e8d002c0113f7c863fbbf4120605dc7e5306b87e3a2af100211dd95d20121cf9400724e9b56879e25451e7751b969aae70d9a835d3264467577f78ac82d9af866220367f948ffe17a0a9fa4c6cc4df3bf567b23db400de87fcd5bb9e6db972479133d2a44057a9ea35e32b0b7a7dad816fae6854badded183b599c33280877b1b9b57e737d7360328656ee0ae73a3e8e66fcaa640f62e9cb89aa32780a2ddab062846d4002094029cada88c93883c67d6f4a2d59676812caa7af534863d8d5a6af0d2195da2096d1c8a27e612e5eacf488338222048deaa2b677db5a03ec2cf9364d5ed4f1e4643890b66425dbf43804b"
        },
        "extensions": {
          "key_usage": [
            "digitalSignature",
            "keyEncipherment"
          ],
          "extended_key_usage": [
            "serverAuth"
          ],
          "CA": false,
          "subject_key_identifier": "b8797f819971523812ef946505cb1cf95373c511",
          "authority_key_identifier": {
            "keyid": "de1b1eed7915d43e3724c321bbec34396d42b230"
          },
          "ca_information_access": {
            "OCSP": "http://o.pki.goog/wr2",
            "CA Issuers": "http://i.pki.goog/wr2.crt"
          },
          "subject_alternative_name": [
            "dns.google",
            "dns.google.com",
            "*.dns.google.com",
            "8888.google",
            "dns64.dns.google",
            "8.8.8.8",
            "8.8.4.4",
            "2001:4860:4860::8888",
            "2001:4860:4860::8844",
            "2001:4860:4860::6464",
            "2001:4860:4860::64"
          ],
          "certificate_policies": [
            "2.23.140.1.2.1"
          ],
          "crl_distribution_points": [
            "http://c.pki.goog/wr2/oQ6nyr8F0m0.crl"
          ],
          "1.3.6.1.4.1.11129.2.4.2": "0481f100ef007600ccfb0f6a85710965fe959b53cee9b27c22e9855c0d978db6"
        },
        "validity": {
          "not_after": "2025-09-29 08:35:57",
          "not_before": "2025-07-07 08:35:58"
        },
        "size": 1461,
        "version": "V3",
        "public_key": {
          "algorithm": "RSA",
          "rsa": {
            "modulus": "8f753a1d9a715147b659c6e1402d17ed774311933f0fd881688538b30e42fe09865a80870291d71eabdf51597e7917437bdbe6488ee3dab12433c8b5d09116eeb818154c35e88cb6d1544beab627410163338c3d9dddfeadfeae579e10d057d49527570a04a2259a0ff1a26c26b32a177bc65abf6e6d85f71e9a3d85117a178e1327d12ac25bbcdca6d3af7f0f2a3d7df6bb6ece2038c0aa38de86c1b238ccdf4cd10edee0e91f166a003646a732acceee596cda5b8b23d7bffd28a4d6ab29cee31c0c835d73e312508af09c03ff7657f343b8ec1e33b9fe3d9656fc99739003cf8af3ededfaeab9e99616b248831fa5778a49e3d5673ea97ebfc5a4a70de665",
            "exponent": "10001",
            "key_size": 2048
          }
        },
        "thumbprint_sha256": "649981865a3effb5ff7be7c842e336ea61f14f5696cc1bde9b068dd03cd6c29d",
        "thumbprint": "731bceed54fa81fc066acd8324f47dd16be28757",
        "serial_number": "f6dd595b0c2839cd0912a6e66311be3a",
        "issuer": {
          "C": "US",
          "O": "Google Trust Services",
          "CN": "WR2"
        },
        "subject": {
          "CN": "dns.google"
        }
      },
      "mandiant_ic_score": 0,
      "tags": [],
      "total_votes": {
        "harmless": 236,
        "malicious": 44
      },
      "first_seen_itw_date": 1409607591,
      "threat_severity": {
        "version": "I3",
        "threat_severity_level": "SEVERITY_NONE",
        "threat_severity_data": {
          "has_bad_communicating_files_high": true,
          "has_bad_communicating_files_medium": true,
          "belongs_to_bad_collection": true
        },
        "last_analysis_date": "1754268022",
        "level_description": "Severity NONE because it has no detections."
      },
      "regional_internet_registry": "ARIN",
      "reputation": 556,
      "whois": "NetRange: 8.8.8.0 - 8.8.8.255\nCIDR: 8.8.8.0/24\nNetName: GOGL\nNetHandle: NET-8-8-8-0-2\nParent: NET8 (NET-8-0-0-0-0)\nNetType: Direct Allocation\nOriginAS: \nOrganization: Google LLC (GOGL)\nRegDate: 2023-12-28\nUpdated: 2023-12-28\nRef: https://rdap.arin.net/registry/ip/8.8.8.0\nOrgName: Google LLC\nOrgId: GOGL\nAddress: 1600 Amphitheatre Parkway\nCity: Mountain View\nStateProv: CA\nPostalCode: 94043\nCountry: US\nRegDate: 2000-03-30\nUpdated: 2019-10-31\nComment: Please note that the recommended way to file abuse complaints are located in the following links. \nComment: \nComment: To report abuse and illegal activity: https://www.google.com/contact/\nComment: \nComment: For legal requests: http://support.google.com/legal \nComment: \nComment: Regards, \nComment: The Google Team\nRef: https://rdap.arin.net/registry/entity/GOGL\nOrgTechHandle: ZG39-ARIN\nOrgTechName: Google LLC\nOrgTechPhone: +1-650-253-0000 \nOrgTechEmail: arin-contact@google.com\nOrgTechRef: https://rdap.arin.net/registry/entity/ZG39-ARIN\nOrgAbuseHandle: ABUSE5250-ARIN\nOrgAbuseName: Abuse\nOrgAbusePhone: +1-650-253-0000 \nOrgAbuseEmail: network-abuse@google.com\nOrgAbuseRef: https://rdap.arin.net/registry/entity/ABUSE5250-ARIN\n",
      "last_modification_date": 1754560745,
      "network": "8.8.8.0/24",
      "jarm": "29d3fd00029d29d00042d43d00041d598ac0c1012db967bb1ad0ff2491b3ae",
      "whois_date": 1752234768,
      "crowdsourced_context": [
        {
          "timestamp": 1694383565,
          "details": "AsyncRAT botnet C2 server (confidence level: 100%)",
          "title": "ThreatFox IOCs for 2023-09-10",
          "severity": "medium",
          "source": "ArcSight Threat Intelligence"
        }
      ],
      "last_analysis_stats": {
        "malicious": 0,
        "suspicious": 0,
        "undetected": 33,
        "harmless": 61,
        "timeout": 0
      },
      "gti_assessment": {
        "verdict": {
          "value": "VERDICT_BENIGN"
        },
        "contributing_factors": {
          "malicious_sandbox_verdict": false,
          "mandiant_association_report": true,
          "gti_confidence_score": 0,
          "mandiant_confidence_score": 0,
          "normalised_categories": [
            "phishing",
            "infostealer",
            "malware",
            "control-server",
            "phishing",
            "malware"
          ],
          "pervasive_indicator": true,
          "mandiant_analyst_benign": true,
          "google_malware_analysis": true
        },
        "severity": {
          "value": "SEVERITY_NONE"
        },
        "threat_score": {
          "value": 0
        },
        "description": "This indicator was determined as benign by a Mandiant analyst and likely poses no threat."
      }
    }
  }
}
```