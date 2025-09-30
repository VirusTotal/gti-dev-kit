```
Created test file: dummy_private_file.txt

Scanning file: dummy_private_file.txt
Uploading file for scanning...
Analysis started (ID: MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YjBiYWVlOWQyNzlkMzRmYTFkZmQ3MWFhZGI5MDhjM2Y6MTc1NDU2MTE3MQ==), polling for results...
Polling attempt 1/20: Status = queued
Polling attempt 2/20: Status = in-progress
Polling attempt 3/20: Status = in-progress
Polling attempt 4/20: Status = completed
Analysis completed, retrieving final report...

Scan completed successfully!

--- Scan Report ---
File SHA-256: d17f25ecfbcc7857f7bebea469308be0b2580943e96d13a3ad98a13675c4bfc2

Verdict: CLEAN

GTI Assessment:
  threat_score: {'value': 1}
  verdict: {'value': 'VERDICT_UNDETECTED'}
  severity: {'value': 'SEVERITY_NONE'}
  contributing_factors: {'pervasive_indicator': True, 'mandiant_confidence_score': 14, 'mandiant_analyst_malicious': False, 'gti_confidence_score': 19}
  description: This indicator did not match our detection criteria and there is currently no evidence of malicious activity.

====== Full JSON Report ========
 {
  "id": "d17f25ecfbcc7857f7bebea469308be0b2580943e96d13a3ad98a13675c4bfc2",
  "type": "private_file",
  "links": {
    "self": "https://www.virustotal.com/api/v3/private/files/d17f25ecfbcc7857f7bebea469308be0b2580943e96d13a3ad98a13675c4bfc2"
  },
  "attributes": {
    "type_tag": "text",
    "md5": "b0baee9d279d34fa1dfd71aadb908c3f",
    "names": [
      "dummy_private_file.txt"
    ],
    "type_tags": [
      "text"
    ],
    "size": 5,
    "meaningful_name": "dummy_private_file.txt",
    "sha1": "7b21848ac9af35be0ddb2d6b9fc3851934db8420",
    "exiftool": {
      "MIMEType": "text/plain",
      "FileType": "TXT",
      "WordCount": "1",
      "LineCount": "1",
      "MIMEEncoding": "us-ascii",
      "FileTypeExtension": "txt",
      "Newlines": "(none)"
    },
    "last_analysis_date": 1754561171,
    "type_description": "Text",
    "magic": "ASCII text, with no line terminators",
    "available_tools": [],
    "threat_severity": {
      "version": 5,
      "threat_severity_level": "SEVERITY_NONE",
      "threat_severity_data": {},
      "last_analysis_date": "1754545666",
      "level_description": "No severity score data"
    },
    "trid": [
      {
        "file_type": "file seems to be plain text/ASCII",
        "probability": 0.0
      }
    ],
    "ssdeep": "3:NG:I",
    "sha256": "d17f25ecfbcc7857f7bebea469308be0b2580943e96d13a3ad98a13675c4bfc2",
    "expiration": 1754647570,
    "type_extension": "txt",
    "magika": "TXT",
    "threat_verdict": "VERDICT_UNDETECTED",
    "tags": [
      "text"
    ],
    "gti_assessment": {
      "threat_score": {
        "value": 1
      },
      "verdict": {
        "value": "VERDICT_UNDETECTED"
      },
      "severity": {
        "value": "SEVERITY_NONE"
      },
      "contributing_factors": {
        "pervasive_indicator": true,
        "mandiant_confidence_score": 14,
        "mandiant_analyst_malicious": false,
        "gti_confidence_score": 19
      },
      "description": "This indicator did not match our detection criteria and there is currently no evidence of malicious activity."
    }
  }
}
```