```
Starting analysis for: www.google.com

Fetching Domain analysis report...
No cache file found for www.google.com. Fetching data from API...
Successfully saved report to cache file: cache\domain_www.google.com_cache_file.json

--- Domain Threat Intelligence Report for www.google.com ---
A deep link back to the full report in the GTI user interface: https://www.virustotal.com/gui/domain/www.google.com

Verdict: Clean

GTI Assessment:
  verdict: {'value': 'VERDICT_BENIGN'}
  threat_score: {'value': 0}
  severity: {'value': 'SEVERITY_NONE'}
  contributing_factors: {'malicious_sandbox_verdict': False, 'mandiant_confidence_score': 0, 'mandiant_association_report': True, 'mandiant_analyst_benign': True, 'gti_confidence_score': 0, 'normalised_categories': ['phishing', 'download-location', 'download-location'], 'mandiant_domain_hijack': True, 'associated_malware_configuration': True, 'pervasive_indicator': True, 'google_malware_analysis': True}
  description: This indicator was determined as benign by a Mandiant analyst and likely poses no threat.

====== Full JSON Report ========
 {
  "data": {
    "id": "www.google.com",
    "type": "domain",
    "links": {
      "self": "https://www.virustotal.com/api/v3/domains/www.google.com"
    },
    "attributes": {
      "first_seen_itw_date": 1,
      "categories": {
        "BitDefender": "searchengines",
        "Sophos": "search engines",
        "Forcepoint ThreatSeeker": "search engines and portals"
      },
      "total_votes": {
        "harmless": 89,
        "malicious": 15
      },
      "creation_date": 874306800,
      "last_update_date": 1722565053,
      "expiration_date": 1852516800,
      "reputation": 212,
      "last_analysis_date": 1754552970,
      "tags": [],
      "whois": "Creation Date: 1997-09-15T04:00:00Z\nCreation Date: 1997-09-15T07:00:00+0000\nDNSSEC: unsigned\nDomain Name: GOOGLE.COM\nDomain Name: google.com\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\nDomain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)\nDomain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)\nDomain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)\nDomain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\nName Server: NS1.GOOGLE.COM\nName Server: NS2.GOOGLE.COM\nName Server: NS3.GOOGLE.COM\nName Server: NS4.GOOGLE.COM\nName Server: ns1.google.com\nName Server: ns2.google.com\nName Server: ns3.google.com\nName Server: ns4.google.com\nRegistrant Country: US\nRegistrant Email: ca4484b9e50182bds@\nRegistrant Organization: 3307059bbb3149c4\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2086851750\nRegistrar IANA ID: 292\nRegistrar Registration Expiration Date: 2028-09-13T07:00:00+0000\nRegistrar URL: http://www.markmonitor.com\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar: MarkMonitor Inc.\nRegistrar: MarkMonitor, Inc.\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN\nRegistry Expiry Date: 2028-09-14T04:00:00Z\nUpdated Date: 2019-09-09T15:39:04Z\nUpdated Date: 2024-08-02T02:17:33+0000",
      "threat_severity": {
        "version": "D3",
        "threat_severity_level": "SEVERITY_NONE",
        "threat_severity_data": {
          "has_bad_communicating_files_high": true,
          "has_bad_communicating_files_medium": true,
          "belongs_to_bad_collection": true,
          "belongs_to_threat_actor": true,
          "domain_rank": "5"
        },
        "last_analysis_date": "1754246803",
        "level_description": "Severity NONE because it has no detections."
      },
      "last_dns_records_date": 1754552971,
      "last_dns_records": [
        {
          "type": "AAAA",
          "ttl": 300,
          "value": "2607:f8b0:4001:c68::68"
        },
        {
          "type": "AAAA",
          "ttl": 300,
          "value": "2607:f8b0:4001:c68::93"
        },
        {
          "type": "A",
          "ttl": 239,
          "value": "64.233.179.147"
        },
        {
          "type": "AAAA",
          "ttl": 300,
          "value": "2607:f8b0:4001:c68::69"
        },
        {
          "type": "A",
          "ttl": 239,
          "value": "64.233.179.104"
        },
        {
          "type": "AAAA",
          "ttl": 300,
          "value": "2607:f8b0:4001:c68::67"
        },
        {
          "type": "A",
          "ttl": 239,
          "value": "64.233.179.106"
        },
        {
          "type": "A",
          "ttl": 239,
          "value": "64.233.179.99"
        },
        {
          "type": "A",
          "ttl": 239,
          "value": "64.233.179.103"
        },
        {
          "type": "A",
          "ttl": 239,
          "value": "64.233.179.105"
        }
      ],
      "last_seen_itw_date": 1754524908,
      "favicon": {
        "raw_md5": "776802e980e0f2a59043a78be5528339",
        "dhash": "e0ce46a7a786cef0"
      },
      "popularity_ranks": {
        "Cisco Umbrella": {
          "rank": 5,
          "timestamp": 1754491082
        }
      },
      "registrar": "MarkMonitor Inc.",
      "last_https_certificate": {
        "cert_signature": {
          "signature_algorithm": "sha256RSA",
          "signature": "72aff0d87f75e8b6c9df0ea99d6470b8cbb2bc5e807cfb6c1f212d7c5429bfb317205ea823ce7ee6e560b10e8cc4e09bf43a13af68046a2093150e7756bb6044a191365dcf6728abcbc63f4bbfc74bbdd1c34b05aa206a751e53b2fb5a38539fe29c6dc54b1636fd57ccf2ea1b05130840b6a4c8cb78616514d398feb2b125c470604e14a5585941e3f5bb9e4851dde04dc965cdc39b7d18e3b8543a775fb57ce51d5f27fa86fcde7b2d25cbb1a0b831a8ef58ea1bb24a8c3e565a761c076f03dc5fbee5ecb4fdb33014a2b0661a45a0ef06d92fcd7bac0c560905bcdc5cdb824bf9a5205c3b7478af83f3e04abb26ceb33976ad146c7e0ddcbc8b1079f5a339"
        },
        "extensions": {
          "key_usage": [
            "digitalSignature"
          ],
          "extended_key_usage": [
            "serverAuth"
          ],
          "CA": false,
          "subject_key_identifier": "887e5e831d1323851ab041f6589af174417c8011",
          "authority_key_identifier": {
            "keyid": "de1b1eed7915d43e3724c321bbec34396d42b230"
          },
          "ca_information_access": {
            "OCSP": "http://o.pki.goog/wr2",
            "CA Issuers": "http://i.pki.goog/wr2.crt"
          },
          "subject_alternative_name": [
            "www.google.com"
          ],
          "certificate_policies": [
            "2.23.140.1.2.1"
          ],
          "crl_distribution_points": [
            "http://c.pki.goog/wr2/oBFYYahzgVI.crl"
          ],
          "1.3.6.1.4.1.11129.2.4.2": "0481f100ef00760012f14e34bd53724c840619c38f3f7a13f8e7b56287889c6d"
        },
        "validity": {
          "not_after": "2025-09-29 08:35:53",
          "not_before": "2025-07-07 08:35:54"
        },
        "size": 1113,
        "version": "V3",
        "public_key": {
          "algorithm": "EC",
          "ec": {
            "oid": "secp256r1",
            "pub": "3059301306072a8648ce3d020106082a8648ce3d0301070342000459941b6f2e4878c0b28c9d8ae9b2aa19e86a3b4a628cc04ff5fae6f754a6800f49721f430d4308a562418ba5c43fe03af09e87205ed4df723e5b6c8d573e878b"
          }
        },
        "thumbprint_sha256": "bf6d12a9d7ab316556638f974e125158559a758194f834d14646484b34cb8a9e",
        "thumbprint": "f3966e68013412ad6a03d8efbd47e1fda4aafbc5",
        "serial_number": "7394c2da72eb55fe0ac352fc6b5ed7c9",
        "issuer": {
          "C": "US",
          "O": "Google Trust Services",
          "CN": "WR2"
        },
        "subject": {
          "CN": "www.google.com"
        }
      },
      "last_https_certificate_date": 1754552971,
      "jarm": "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d",
      "last_analysis_stats": {
        "malicious": 0,
        "suspicious": 0,
        "undetected": 29,
        "harmless": 65,
        "timeout": 0
      },
      "tld": "com",
      "mandiant_ic_score": 0,
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
          "category": "harmless",
          "result": "clean"
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
          "category": "harmless",
          "result": "clean"
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
          "category": "harmless",
          "result": "clean"
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
          "category": "harmless",
          "result": "clean"
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
      "last_modification_date": 1754560427,
      "gti_assessment": {
        "verdict": {
          "value": "VERDICT_BENIGN"
        },
        "threat_score": {
          "value": 0
        },
        "severity": {
          "value": "SEVERITY_NONE"
        },
        "contributing_factors": {
          "malicious_sandbox_verdict": false,
          "mandiant_confidence_score": 0,
          "mandiant_association_report": true,
          "mandiant_analyst_benign": true,
          "gti_confidence_score": 0,
          "normalised_categories": [
            "phishing",
            "download-location",
            "download-location"
          ],
          "mandiant_domain_hijack": true,
          "associated_malware_configuration": true,
          "pervasive_indicator": true,
          "google_malware_analysis": true
        },
        "description": "This indicator was determined as benign by a Mandiant analyst and likely poses no threat."
      }
    }
  }
}
```