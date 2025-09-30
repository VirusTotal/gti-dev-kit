# Google Threat Intelligence (GTI) Dashboard

This repository provides documentation and configuration details for integrating a Google Threat Intelligence (GTI) Dashboard into security platforms to visualize and analyze threat intelligence data. The dashboard encompasses **Threat Intelligence**, **Adversary Intelligence**, **Threat List**, **IOC Stream**, and **MITRE ATT&CK** sections, offering comprehensive insights into flagged files, domains, URLs, IP addresses, VPN/Tor/Proxy IPs, adversary activities, threat lists, IOC streams, and MITRE ATT&CK tactics and techniques. It leverages GTI's robust threat data to support security operations, incident response, and threat hunting with actionable visualizations.

This dashboard is provided only as an example. Users can create their own dashboard tailored to their specific needs within their platform.

## 1. Threat Intelligence Dashboard

The Threat Intelligence dashboard provides detailed information about Threats.

### Files
The Files section provides insights into malicious flagged files based on file events where `attributes.last_analysis_stats.malicious > 0`.

| Panel | Type | Field | Description |
|-------|------|-------|-------------|
| Total Flagged Files | Number | Based on file events, Condition: `attributes.last_analysis_stats.malicious > 0` | Displays the count of malicious flagged files. |
| Flagged Files by File Type | Pie | `attributes.type_tag` | Displays the count of each file type for flagged files. |
| Flagged Files by Threat Label | Pie | `gti_assessment.popular_threat_classification.suggested_threat_label` | Displays the count of each threat label (e.g., trojan.upatre/zbot) for flagged files. |
| Flagged Files by Verdict | Pie | `gti_assessment.verdict.value` | Displays the count of each verdict for flagged files. |
| Flagged Files Summary | Table | ID: `id`<br>Threat Score: `gti_assessment.threat_score.value`<br>Verdict: `gti_assessment.verdict.value`<br>Severity: `gti_assessment.severity.value`<br>Detection: `attributes.last_analysis_stats.malicious`<br>File Type: `attributes.type_tag`<br>Last seen in events: Event ingestion time<br>First seen in GTI: `attributes.first_submission_date`<br>Threat Label: `gti_assessment.popular_threat_classification.suggested_threat_label`<br>Comments: Count of `relationships.comments.data`<br>Yara Rule: Count of `attributes.crowdsourced_yara_results`<br>Actions: Full Report | Displays recent flagged file details within the selected time range. Includes actions like “Full Report” (redirects to Google Threat Intelligence platform) and “Comments” (displays comments in Platform log activity). |

### Domains
The Domains section focuses on malicious flagged domains based on file events where `attributes.last_analysis_stats.malicious > 0`.

| Panel | Type | Field | Description |
|-------|------|-------|-------------|
| Total Flagged Domains | Number | Based on file events, Condition: `attributes.last_analysis_stats.malicious > 0` | Displays the count of malicious flagged domains. |
| Flagged Domains by Category | Pie | `attributes.categories` | Displays the count of each category for flagged domains. |
| Flagged Domains by Top-Level Domain | Pie | `attributes.tld` | Displays the count of each top-level domain for flagged domains. |
| Flagged Domains by Verdict | Pie | `gti_assessment.verdict.value` | Displays the count of each verdict for flagged domains. |
| Flagged Domains Summary | Table | ID: `id`<br>Threat Score: `gti_assessment.threat_score.value`<br>Verdict: `gti_assessment.verdict.value`<br>Severity: `gti_assessment.severity.value`<br>Detection: `attributes.last_analysis_stats.malicious`<br>Tags: `attributes.tags`<br>Last seen in events: Event ingestion time<br>Creation Date: `attributes.creation_date`<br>Comments: Count of `relationships.comments.data`<br>Actions: Full Report | Displays recent flagged domain details within the selected time range. Includes actions like “Full Report” and “Comments”. |

### URLs
The URLs section provides details on malicious flagged URLs based on file events where `attributes.last_analysis_stats.malicious > 0`.

| Panel | Type | Field | Description |
|-------|------|-------|-------------|
| Total Flagged URLs | Number | Based on file events, Condition: `attributes.last_analysis_stats.malicious > 0` | Displays the count of malicious flagged URLs. |
| Flagged URLs by Category | Pie | `attributes.categories` | Displays the count of each category for flagged URLs. |
| Flagged URLs by Top-Level Domain | Pie | `attributes.tld` | Displays the count of each top-level domain for flagged URLs. |
| Flagged URLs by Verdict | Pie | `gti_assessment.verdict.value` | Displays the count of each verdict for flagged URLs. |
| Flagged URLs Summary | Table | URL: `attributes.url`<br>Threat Score: `gti_assessment.threat_score.value`<br>Verdict: `gti_assessment.verdict.value`<br>Severity: `gti_assessment.severity.value`<br>Detection: `attributes.last_analysis_stats.malicious`<br>Tags: `attributes.tags`<br>Last seen in events: Event ingestion time<br>Comments: Count of `relationships.comments.data`<br>Actions: Full Report | Displays recent flagged URL details within the selected time range. Includes actions like “Full Report” and “Comments”. |

### IPs
The IPs section covers malicious flagged IP addresses based on file events where `attributes.last_analysis_stats.malicious > 0`.

| Panel | Type | Field | Description |
|-------|------|-------|-------------|
| Total Flagged IP Addresses | Number | Based on file events, Condition: `attributes.last_analysis_stats.malicious > 0` | Displays the count of malicious flagged IP addresses. |
| Flagged IP Addresses by Country | Pie | `attributes.country` | Displays the count of each country for flagged IP addresses. |
| Flagged IP Addresses by Autonomous System Owner | Pie | `attributes.as_owner` | Displays the count of each autonomous system owner for flagged IP addresses. |
| Flagged IP Addresses by Verdict | Pie | `gti_assessment.verdict.value` | Displays the count of each verdict for flagged IP addresses. |
| Flagged IP Summary | Table | IP Address: `id`<br>Threat Score: `gti_assessment.threat_score.value`<br>Verdict: `gti_assessment.verdict.value`<br>Severity: `gti_assessment.severity.value`<br>Detections: `attributes.last_analysis_stats.malicious`<br>Tags: `attributes.tags`<br>Country: `attributes.country`<br>Network: `attributes.network`<br>Autonomous System: `attributes.as_owner`<br>Last seen in events: Event ingestion time<br>Comments: Count of `relationships.comments.data`<br>Actions: Full Report | Displays recent flagged IP address details within the selected time range. Includes actions like “Full Report” and “Comments”. |

### VPN, Tor, and Proxy IPs
This section focuses on IP addresses tagged as VPN, Tor, or Proxy, based on file events where `attributes.last_analysis_stats.malicious > 0` or `attributes.tags` contains “vpn”, “tor”, or “proxy”.

| Panel | Type | Field | Description |
|-------|------|-------|-------------|
| Total Flagged IP Addresses | Number | Based on file events, Condition: `attributes.last_analysis_stats.malicious > 0` OR `attributes.tags` CONTAINS (“vpn”, “tor”, “proxy”) | Displays the count of threats tagged as VPN, Tor, or Proxy IPs. |
| Flagged IP Addresses by Country | Pie | `attributes.country` | Displays the count of each country for flagged IP addresses. |
| Flagged IP Addresses by Autonomous System Owner | Pie | `attributes.as_owner` | Displays the count of each autonomous system owner for flagged IP addresses. |
| Flagged IP Addresses by Verdict | Pie | `gti_assessment.verdict.value` | Displays the count of each verdict for flagged IP addresses. |
| Flagged IP Addresses Summary | Table | IP Address: `id`<br>Threat Score: `gti_assessment.threat_score.value`<br>Verdict: `gti_assessment.verdict.value`<br>Severity: `gti_assessment.severity.value`<br>Detections: `attributes.last_analysis_stats.malicious`<br>Tags: `attributes.tags`<br>Country: `attributes.country`<br>Network: `attributes.network`<br>Autonomous System: `attributes.as_owner`<br>Last seen in events: Event ingestion time<br>Comments: Count of `relationships.comments.data`<br>Actions: Full Report | Displays recent flagged IP address details within the selected time range. Includes actions like “Full Report” and “Comments”. |

## 2. Adversary Intelligence Dashboard
The Adversary Intelligence section provides curated and OSINT information about Indicators of Compromise (IoCs) relationships, including Campaigns, Malware Families, Threat Actors, Collections, Software Toolkits, and Reports.

| Panel | Type | Field | Description |
|-------|------|-------|-------------|
| Campaigns Found | Number | Based on Campaigns Event | Displays the count of campaigns. |
| Campaigns Summary | Table | Name: `attributes.name`<br>First seen in events: Current event ingestion time<br>Last seen in events: Current event ingestion time (updated for recurring collections)<br>Description: `attributes.description`<br>Targeted regions: `attributes.targeted_regions`<br>Targeted industries: `attributes.targeted_industries`<br>Collection Type: `attributes.collection_type`<br>Actions: Full Report | Displays recent campaign details within the selected time range. Includes “Full Report” and “IOC Details” actions. |
| Malware Family Found | Number | Based on Malware Family Event | Displays the count of Malware Families. |
| Malware Family Summary | Table | Name: `attributes.name`<br>First seen in events: Current event ingestion time<br>Last seen in events: Current event ingestion time (updated for recurring collections)<br>Description: `attributes.description`<br>Targeted regions: `attributes.targeted_regions`<br>Targeted industries: `attributes.targeted_industries`<br>Collection Type: `attributes.collection_type`<br>Actions: Full Report | Displays recent Malware Family details within the selected time range. Includes “Full Report” and “IOC Details” actions. |
| Threat Actors Found | Number | Based on Threat Actors Event | Displays the count of Threat Actors. |
| Threat Actors Summary | Table | Name: `attributes.name`<br>First seen in events: Current event ingestion time<br>Last seen in events: Current event ingestion time (updated for recurring collections)<br>Description: `attributes.description`<br>Targeted regions: `attributes.targeted_regions`<br>Targeted industries: `attributes.targeted_industries`<br>Collection Type: `attributes.collection_type`<br>Actions: Full Report | Displays recent Threat Actor details within the selected time range. Includes “Full Report” and “IOC Details” actions. |
| Collections Found | Number | Based on Collections Event | Displays the count of Collections. |
| Collections Summary | Table | Name: `attributes.name`<br>First seen in events: Current event ingestion time<br>Last seen in events: Current event ingestion time (updated for recurring collections)<br>Description: `attributes.description`<br>Targeted regions: `attributes.targeted_regions`<br>Targeted industries: `attributes.targeted_industries`<br>Collection Type: `attributes.collection_type`<br>Actions: Full Report | Displays recent Collection details within the selected time range. Includes “Full Report” and “IOC Details” actions. |
| Software Toolkit Found | Number | Based on Software Toolkit Event | Displays the count of Software Toolkits. |
| Software Toolkit Summary | Table | Name: `attributes.name`<br>First seen in events: Current event ingestion time<br>Last seen in events: Current event ingestion time (updated for recurring collections)<br>Description: `attributes.description`<br>Targeted regions: `attributes.targeted_regions`<br>Targeted industries: `attributes.targeted_industries`<br>Collection Type: `attributes.collection_type`<br>Actions: Full Report | Displays recent Software Toolkit details within the selected time range. Includes “Full Report” and “IOC Details” actions. |
| Reports Found | Number | Based on Reports Event | Displays the count of Reports. |
| Reports Summary | Table | Name: `attributes.name`<br>First seen in events: Current event ingestion time<br>Last seen in events: Current event ingestion time (updated for recurring collections)<br>Description: `attributes.description`<br>Targeted regions: `attributes.targeted_regions`<br>Targeted industries: `attributes.targeted_industries`<br>Collection Type: `attributes.collection_type`<br>Actions: Full Report | Displays recent Report details within the selected time range. Includes “Full Report” and “IOC Details” actions. |

## 3. Threat List Dashboard
The Threat List section provides insights into ingested indicators and their severity levels.

| Panel | Type | Field | Description |
|-------|------|-------|-------------|
| Total Ingested Indicators | Number | Based on Threat List event | Displays the count of ingested indicators. |
| High Severity | Number | `gti_assessment.severity.value = "SEVERITY_HIGH"` | Displays the count of high-severity indicators. |
| Medium Severity | Number | `gti_assessment.severity.value = "SEVERITY_MEDIUM"` | Displays the count of medium-severity indicators. |
| Low Severity | Number | `gti_assessment.severity.value = "SEVERITY_LOW"` | Displays the count of low-severity indicators. |
| None Severity | Number | `gti_assessment.severity.value = "SEVERITY_NONE"` | Displays the count of none-severity indicators. |
| Unknown Severity | Number | `gti_assessment.severity.value = "SEVERITY_UNKNOWN"` | Displays the count of unknown-severity indicators. |
| Ingested Indicators Over Time | Area Chart | Based on event ingested time | Displays the trend of ingested indicators over time. |
| Ingested Indicators By Type | Pie | `data.type` | Displays the count of each indicator type. |
| Ingested Indicators By Categorized Threat List | Pie | Threat list type | Displays the count of indicators by categorized threat list. |

## 4. IOC Stream Dashboard
The IOC Stream section mirrors the Threat List section, focusing on ingested indicators.

| Panel | Type | Field | Description |
|-------|------|-------|-------------|
| Total Ingested Indicators | Number | Based on Threat List event | Displays the count of ingested indicators. |
| High Severity | Number | `gti_assessment.severity.value = "SEVERITY_HIGH"` | Displays the count of high-severity indicators. |
| Medium Severity | Number | `gti_assessment.severity.value = "SEVERITY_MEDIUM"` | Displays the count of medium-severity indicators. |
| Low Severity | Number | `gti_assessment.severity.value = "SEVERITY_LOW"` | Displays the count of low-severity indicators. |
| None Severity | Number | `gti_assessment.severity.value = "SEVERITY_NONE"` | Displays the count of none-severity indicators. |
| Unknown Severity | Number | `gti_assessment.severity.value = "SEVERITY_UNKNOWN"` | Displays the count of unknown-severity indicators. |
| Ingested Indicators Over Time | Area Chart | Based on event ingested time | Displays the trend of ingested indicators over time. |
| Ingested Indicators By Type | Pie | `type` | Displays the count of each indicator type. |

## 5. MITRE ATT&CK Dashboard
The MITRE ATT&CK section provides detailed information about attack tactics and techniques, with drill-down capabilities to log activity.

| Panel | Type | Field | Description |
|-------|------|-------|-------------|
| ATT&CK Techniques Found | Table | MITRE ATT&CK Tactic: `data.${sanbox_name}.tactics`<br>MITRE ATT&CK Technique: `data.${sanbox_name}.tactics.techniques`<br>File Hash: File hash<br>Sandbox: `data.${sanbox_name}`<br>First Ingested in Platform: First ingested time<br>Last Ingested in Platform: Last ingested time<br>Sandbox Signature Severity: `data.${sanbox_name}.tactics.techniques.signatures.severity`<br>Actions: Full Report | Displays recent ATT&CK Techniques found. Includes “Full Report” and “IOC Details” actions for in-depth details on the Google Threat Intelligence platform and Platform log activity. |

This README provides a structured overview of the Dashboard, enabling users to understand and navigate its features effectively for threat monitoring and analysis.