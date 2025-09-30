```
Using default URL: https://www.youtube.com/

Scanning URL: https://www.youtube.com/
Submitting URL for scanning: https://www.youtube.com/
Analysis started (ID: ZDk4N2IxMjFhNTBiMDE3OGZhZWFmOTVhZDc3YzE3ODM6ZGJhZTJkMDIwNGFhNDg5ZTIzNGViMmY5MDNhMDEyN2IxN2M3MTIzODY0MjhjYWIxMmI4NmM1ZjY4YWE3NTg2NzoxNzU0NTYxMjU5), polling for results...
Polling attempt 1/20: Status = queued
Polling attempt 2/20: Status = queued
Polling attempt 3/20: Status = completed
Analysis completed, retrieving final report...

Scan completed successfully!

=== URL Scan Report ===

Verdict: CLEAN

GTI Assessment:
  severity: {'value': 'SEVERITY_NONE'}
  threat_score: {'value': 1}
  verdict: {'value': 'VERDICT_UNDETECTED'}
  contributing_factors: {'safebrowsing_verdict': 'harmless', 'pervasive_indicator': True, 'mandiant_confidence_score': 3, 'gti_confidence_score': 3}
  description: This indicator did not match our detection criteria and there is currently no evidence of malicious activity.

====== Full JSON Report ========
 {
  "id": "dbae2d0204aa489e234eb2f903a0127b17c712386428cab12b86c5f68aa75867",
  "type": "private_url",
  "links": {
    "self": "https://www.virustotal.com/api/v3/private/urls/dbae2d0204aa489e234eb2f903a0127b17c712386428cab12b86c5f68aa75867"
  },
  "attributes": {
    "favicon": {
      "raw_md5": "50ce85284e2280149608626d73f8294f",
      "dhash": "00a65ab2b25aa600"
    },
    "expiration": 1754647659,
    "title": "YouTube",
    "last_http_response_code": 200,
    "url": "https://www.youtube.com/",
    "outgoing_links": [
      "https://accounts.google.com/ServiceLogin?service=youtube&uilel=3&passive=true&continue=https%3A%2F%2Fwww.youtube.com%2Fsignin%3Faction_handle_signin%3Dtrue%26app%3Ddesktop%26hl%3Den%26next%3Dhttps%253A%252F%252Fwww.youtube.com%252F&hl=en&ec=65620",
      "https://accounts.google.com/ServiceLogin?service=youtube&uilel=3&passive=true&continue=https%3A%2F%2Fwww.youtube.com%2Fsignin%3Faction_handle_signin%3Dtrue%26app%3Ddesktop%26hl%3Den%26next%3Dhttps%253A%252F%252Fwww.youtube.com%252F&hl=en",
      "https://tv.youtube.com/?utm_source=youtube_web&utm_medium=ep&utm_campaign=home&ve=34273",
      "https://music.youtube.com/",
      "https://www.youtubekids.com/?source=youtube_web",
      "https://developers.google.com/youtube",
      "https://static.doubleclick.net/instream/ad_status.js",
      "https://www.gstatic.com/cv/js/sender/v1/cast_sender.js",
      "https://accounts.google.com/ServiceLogin?service=youtube&uilel=3&passive=true&continue=https%3A%2F%2Fwww.youtube.com%2Fsignin%3Faction_handle_signin%3Dtrue%26app%3Ddesktop%26hl%3Den%26next%3D%252Fsignin_passive%26feature%3Dpassive&hl=en",
      "https://www.gstatic.com/youtube/img/emojis/emojis-png-15.1.json",
      "https://apis.google.com",
      "https://accounts.google.com/ServiceLogin?service",
      "https://payments.youtube.com/payments/v4/js/integrator.js?ss",
      "https://families.google.com/webcreation?usegapi",
      "https://client-channel.google.com/client-channel/client",
      "https://clients4.google.com/invalidation/lcs/client",
      "https://youtubei-att.googleapis.com/",
      "https://studio.youtube.com/persist_identity",
      "https://support.google.com/youtube/?p",
      "https://accountlinking-pa-clients6.youtube.com",
      "https://accounts.google.com/ServiceLogin?service=youtube"
    ],
    "html_meta": {
      "og:image": [
        "https://www.youtube.com/img/desktop/yt_1200.png"
      ],
      "fb:app_id": [
        "87741124305"
      ],
      "description": [
        "Enjoy the videos and music you love, upload original content, and share it all with friends, family, and the world on YouTube."
      ],
      "keywords": [
        "video, sharing, camera phone, video phone, free, upload"
      ],
      "theme-color": [
        "rgba(255, 255, 255, 0.98)"
      ],
      "viewport": [
        "width=device-width, initial-scale=1.0, viewport-fit=cover"
      ]
    },
    "last_http_response_content_length": 669259,
    "last_http_response_headers": {
      "content-security-policy-report-only": "script-src 'unsafe-eval' 'self' 'unsafe-inline' https://www.google.com https://apis.google.com https://ssl.gstatic.com https://www.gstatic.com https://www.googletagmanager.com https://www.google-analytics.com https://*.youtube.com https://*.google.com https://*.gstatic.com https://youtube.com https://www.youtube.com https://google.com https://*.doubleclick.net https://*.googleapis.com https://www.googleadservices.com https://tpc.googlesyndication.com https://www.youtubekids.com https://www.youtube-nocookie.com https://www.youtubeeducation.com;report-uri /cspreport/allowlist",
      "document-policy": "include-js-call-stacks-in-crash-reports",
      "expires": "Mon, 01 Jan 1990 00:00:00 GMT",
      "permissions-policy": "ch-ua-arch=*, ch-ua-bitness=*, ch-ua-full-version=*, ch-ua-full-version-list=*, ch-ua-model=*, ch-ua-wow64=*, ch-ua-form-factors=*, ch-ua-platform=*, ch-ua-platform-version=*",
      "pragma": "no-cache",
      "report-to": "{\"group\":\"youtube_main\",\"max_age\":2592000,\"endpoints\":[{\"url\":\"https://csp.withgoogle.com/csp/report-to/youtube_main\"}]}",
      "x-content-type-options": "nosniff",
      "x-frame-options": "SAMEORIGIN",
      "cache-control": "no-cache, no-store, max-age=0, must-revalidate",
      "content-encoding": "br",
      "content-security-policy": "require-trusted-types-for 'script'",
      "date": "Thu, 07 Aug 2025 10:07:41 GMT",
      "server": "ESF",
      "x-xss-protection": "0",
      "origin-trial": "AmhMBR6zCLzDDxpW+HfpP67BqwIknWnyMOXOQGfzYswFmJe+fgaI6XZgAzcxOrzNtP7hEDsOo1jdjFnVr2IdxQ4AAAB4eyJvcmlnaW4iOiJodHRwczovL3lvdXR1YmUuY29tOjQ0MyIsImZlYXR1cmUiOiJXZWJWaWV3WFJlcXVlc3RlZFdpdGhEZXByZWNhdGlvbiIsImV4cGlyeSI6MTc1ODA2NzE5OSwiaXNTdWJkb21haW4iOnRydWV9",
      "strict-transport-security": "max-age=31536000",
      "vary": "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-WoW64, Sec-CH-UA-Form-Factors, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version",
      "accept-ch": "Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Sec-CH-UA-Full-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Model, Sec-CH-UA-WoW64, Sec-CH-UA-Form-Factors, Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version",
      "content-type": "text/html; charset=utf-8",
      "cross-origin-opener-policy": "same-origin-allow-popups; report-to=\"youtube_main\"",
      "p3p": "CP=\"This is not a P3P policy! See http://support.google.com/accounts/answer/151657?hl=en for more info.\"",
      "reporting-endpoints": "default=\"/web-reports?context=eJwNzmtIk3EUBnD_PlG6d3vf9xw_RBYUIgXlZCmzKCsqMjEswy7WjDnXthR1ZtucZBGhpShSWXkv-qISaGIQiNoNwYgupEWQSmRUSJoVaJKV_T_8PjzncHiOoWtRcV-u8Czki-jkAtF15qTIXFMkdr08JaqTfGK21Sc6en1iclVA2KICov5NQOS9D4r5j0FxQ88IdUdmhAal3qMGuN0GzDQY8GPUgOC0AbZ1CkyxCoZTFEzuVXCvTUFvt4KxLwr8NiO-Zxlh9RvhnTViIs2E_gYThoZNcIybEHNARWK1ivYeFWmDKi5Lnj8qvv1VkbBFQ-duDQGXBiWgobFSw_o6DWG3NCx9qqE_WkdYlg6DZL2mY6hJR_gdHaO_dGz-reNYBMG3luCwEmqkhE2Esm2EPemE5oOEMTsh1UNw5hJKS-VOcpYTtlcRXlQTdtQQpmsJcVcJW68THtwmjHQQlncSFu4Twp_I_JwQ8ZqwYoKwYZowPkc4MU_w_CNcCmGo4Yz8ZYxHkYz6lYxPUYz4eIYjkdG2k3E3ifFOiklmLKQwWvYxQvYzvh5mpNoYHzIZhXbGvIdhPS1nZxniHGPuPKOqnDF1gVFWwVhSyUi_wjhSy8iuY8w0Mg41MZpvMtxtjIvtsl_ydjNW9zBKJG-fvHvIMD6Wfw4yBp4xhqXit4yKEQYbw6ZmXg0s1us__2xFlLnE6_f5s12xxa5ss7vIW-AzuwqOm51FOb4cpyPPHmeJs1o2WhJiLRZ7oeU_2IC2KA\""
    },
    "last_final_url": "https://www.youtube.com/",
    "tags": [
      "iframes",
      "external-resources"
    ],
    "tld": "com",
    "redirection_chain": [
      "https://www.youtube.com/"
    ],
    "last_http_response_content_sha256": "a16ed6dbfc8274a4e8f6e11736bd432e8551acd3312e681f9fcac5ae9f3e4b64",
    "gti_assessment": {
      "severity": {
        "value": "SEVERITY_NONE"
      },
      "threat_score": {
        "value": 1
      },
      "verdict": {
        "value": "VERDICT_UNDETECTED"
      },
      "contributing_factors": {
        "safebrowsing_verdict": "harmless",
        "pervasive_indicator": true,
        "mandiant_confidence_score": 3,
        "gti_confidence_score": 3
      },
      "description": "This indicator did not match our detection criteria and there is currently no evidence of malicious activity."
    }
  }
}
```