# Google Threat Intelligence (GTI) Enrichment Scripts

This repository contains a collection of Python scripts designed to interface with the Google Threat Intelligence (GTI) API to provide detailed threat intelligence for various Indicators of Compromise (IOCs). These scripts support both **manual** and **automatic enrichment** workflows, enabling security analysts, incident responders, and threat hunters to assess the reputation, risk, and broader threat context of IOCs such as IP addresses, domains, URLs, and file hashes (MD5, SHA-1, SHA-256).

## Overview

The scripts streamline threat intelligence workflows by fetching, caching, and presenting enriched metadata from the GTI API. They are designed to support security operations by providing actionable insights into IOCs, including verdicts, detection statistics, relationships to threat actors, malware families, campaigns, and vulnerabilities, as well as sandbox behavior and MITRE ATT&CK mappings for files. Each script includes robust error handling, local caching for performance optimization, and structured output for easy consumption.

## Manual IOC Enrichment
  - **Objective**: Enable analysts to instantly retrieve detailed threat context for an IOC directly from a security platform's UI.
  - **Implementation Details**:
      - Supports IPs, domains, URLs, and file hashes.
      - Designed for integration as a one-click button or right-click context menu action (e.g., "Enrich IOC" or type-specific actions like "Enrich IP Address").
      - Prioritizes critical results: verdict (malicious/clean), GTI score, and associated threat actor names.
      - Includes deep links to the GTI GUI for deeper investigation.
      - For file-based IOCs, integrates MITRE ATT&CK TTP visuals to map adversary behaviors.
      - Optionally supports generating a GTI widget for concise presentation of findings.
  - **Relevant API Calls**:
      - `/ip_addresses/{ip_address}` (IP reports)
      - `/urls/{url_id}` (URL reports)
      - `/domains/{domain}` (domain reports)
      - `/files/{file_hash}` (file reports)
      - `/files/{file_hash}/behaviours` (file sandbox behaviors)
      - `/files/{file_hash}/behaviour_mitre_trees` (MITRE ATT&CK mappings)
  - **Configuration Tip**: Ensure the GTI API key and product name are correctly configured to avoid authentication errors.
  - [**Best Practices Guide**](https://docs.google.com/document/d/1foYWa5FnlwtYBIo63YIZU5AOInI7UsNdrn9g0ty25Ag/edit?resourcekey=0-SIeMz9ALACxg0qGd75Jm4g&tab=t.0#heading=h.cv5c87pbf4yf)


## Automatic IOC Enrichment
  - **Objective**: Automatically enrich IOCs in alerts, events, or cases as they are ingested, providing immediate context without manual intervention.
  - **Implementation Details**:
      - Integrates into data ingestion pipelines to process IOCs in real-time.
      - Uses local caching with a configurable Time-To-Live (TTL, e.g., 5-15 minutes) to optimize API quota usage.
      - Flags enriched IOCs in alerts or incident views, displaying summaries like verdict and GTI score.
      - Supports MITRE ATT&CK TTP visuals for enhanced threat detection (file-specific).
  - **Relevant API Calls**: Same as manual enrichment (see above).
  - **Configuration Tip**:
      - Provide granular controls for enabling/disabling enrichment for specific data sources or event types.
      - Configure TTL for caching to balance freshness and API usage.
  - [**Best Practices Guide**](https://docs.google.com/document/d/1foYWa5FnlwtYBIo63YIZU5AOInI7UsNdrn9g0ty25Ag/edit?resourcekey=0-SIeMz9ALACxg0qGd75Jm4g&tab=t.0#heading=h.wi8la7i1vfm9)

## Key Features
  - **Manual Enrichment**: Allows analysts to trigger enrichment directly from a security platform's UI with a one-click or right-click context menu action, displaying critical results like verdicts, GTI scores, and threat actor associations.
  - **Automatic Enrichment**: Integrates with data ingestion pipelines to automatically enrich IOCs in alerts, events, or cases, with configurable caching to optimize API usage.
  - **Support for Multiple IOC Types**: Enrich IPs, domains, URLs, and file hashes (MD5, SHA-1, SHA-256).
  - **Caching Mechanism**: Stores API responses in a `cache/` directory to reduce redundant API calls, improve performance, and enable offline access. Cache files are named systematically (e.g., `cache/ip_8.8.8.8_cache_file.json`).
  - **Structured Output**: Presents verdicts (malicious/clean), detection counts, GTI assessments, and deep links to the GTI web interface in a human-readable format.
  - **Relationship Data**: Retrieves and displays related threat entities, including collections, malware families, threat actors, software toolkits, campaigns, reports, and vulnerabilities.
  - **MITRE ATT&CK Mapping**: For file-based IOCs, includes sandbox behavior analysis and mappings to MITRE ATT&CK tactics and techniques for enhanced threat context.
  - **Sandbox Behavior Analysis**: For files, provides dynamic behavioral observations from sandbox executions, including command executions and behavior identifiers.
  - **Robust Error Handling**: Gracefully handles HTTP errors, connection issues, rate limits (HTTP 429), server errors (HTTP 5xx), and JSON parsing issues, with retry logic for transient failures.
  - **GTI GUI Deep Links**: Provides direct links to the GTI web interface for each IOC, enabling seamless transitions to manual investigation.

## Enrichment Use Cases for SIEM and SOAR
GTI enrichment enhances Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) platforms by providing real-time, actionable threat intelligence.

1. **Automated Incident Response**

  - Trigger SOAR playbooks from SIEM alerts (e.g., blacklisted domain access).
  - Fetch GTI reports for IOCs and execute actions based on verdicts:
      - Block IOCs at firewalls, proxies, or DNS.
      - Isolate affected endpoints.
      - Escalate high-priority incidents linked to known threat actors.
      - Enrich alerts with relationships (e.g., malware, campaigns).

2. **Proactive Threat Hunting**

  - Query GTI for IOCs tied to new malware or threat actors.
  - Correlate with SIEM logs to detect hidden threats early.

3. **Alert Triage and Prioritization**

  - Enrich SIEM alerts with GTI context (e.g., threat classification, campaign associations).
  - Prioritize alerts based on severity and real-world threat intelligence.

4. **Contextualizing Forensic Investigations**

  - Retrieve full IOC context (e.g., vulnerabilities, campaigns).
  - Trace attack lifecycles and inform remediation strategies.

5. **Curated Threat Intelligence Feed**

  - Schedule GTI queries to update internal IOC blacklists.
  - Enhance detection across firewalls, EDRs, and proxies.

## Relationship Data Details
The scripts that focus on relationship data (`enrich_ip_with_relationship.py`, `enrich_url_with_relationship.py`, `enrich_domain_with_relationship.py`, `enrich_file_with_relationship_and_behaviour.py`) retrieve and display related threat entities to provide a broader threat context. The following relationship types are supported:

- **Collection**: 
    - **Description**: Collections of Indicators of Compromise (IoCs) grouped based on their observed usage in malicious campaigns or association with specific malware families.
    - **Source**: Includes Open-Source Intelligence (OSINT) and curated information from GTI users, trusted partners, security researchers, crowdsourced reports from the cybersecurity community, or Google TI experts.
    - **Use Case**: Identifying groups of IoCs linked to specific campaigns or malware for threat hunting.

- **Threat Actor**: 
    - **Description**: Curated information about threat actors tracked by Google TI experts or provided by trusted partners and security researchers.
    - **Source**: Google TI experts, trusted partners, and security researchers.
    - **Use Case**: Linking an IOC to known threat actors to understand their tactics and motivations.

- **Malware Family**: 
    - **Description**: Curated information about malware families, detailing their characteristics and behaviors.
    - **Source**: Google TI experts and trusted partners/security researchers.
    - **Use Case**: Identifying malware families associated with an IOC to assess its potential impact.

- **Software Toolkit**: 
    - **Description**: Curated information about malicious software or toolkits used in threat campaigns.
    - **Source**: Google TI experts.
    - **Use Case**: Understanding the tools used in attacks involving the IOC.

- **Campaign**: 
    - **Description**: Curated information about threat campaigns, including their objectives and scope.
    - **Source**: Google TI experts.
    - **Use Case**: Mapping an IOC to specific threat campaigns for context on attack patterns.

- **Report**: 
    - **Description**: OSINT and curated threat-related reports, which may include crowdsourced references from the cybersecurity industry or curated reports from trusted partners, security researchers, or Google TI experts.
    - **Source**: Cybersecurity community, trusted partners, security researchers, and Google TI experts.
    - **Use Case**: Accessing detailed reports to understand the broader context of an IOC.

- **Vulnerability**: 
    - **Description**: Curated information about vulnerabilities and exploitations identified through Google TI experts' analysis.
    - **Source**: Google TI experts.
    - **Use Case**: Identifying vulnerabilities exploited by an IOC to prioritize remediation.

- **Resolution** (IP and Domain scripts only):
    - **Description**: Information about resolutions related to the IP or domain, such as DNS resolutions or associated endpoints.
    - **Source**: GTI API data.
    - **Use Case**: Understanding how an IP or domain resolves to other entities in the threat landscape.

## Use Case: Adversary Intelligence Threat Analysis
  - **Enrichment Workflow**:
      - Leverage scripts (`enrich_ip_with_relationship.py`, `enrich_url_with_relationship.py`, `enrich_domain_with_relationship.py`, `enrich_file_with_relationship_and_behaviour.py`) to query relationships for IOCs such as domains, file hashes, IPs, or URLs.
      - Retrieve associated entities (e.g., `collection`, `threat-actor`, `malware-family`) to construct a detailed threat profile.
  - **SOAR Integration**:
      - Automate relationship queries within SOAR playbooks to enrich alerts with adversary intelligence in real time.
      - Prioritize and escalate incidents linked to high-profile threat actors or campaigns based on GTI relationship data.
  - **Threat Hunting**:
      - Correlate IOCs with `report` and `vulnerability` data to uncover emerging threats and prioritize mitigation efforts.
      - Use `collection` relationships to identify patterns across multiple IOCs, enabling proactive detection of coordinated attacks.

## Scripts Overview
The repository includes the following scripts, each tailored to a specific IOC type or enrichment goal. Below, each script is described along with its key features and the specific GTI API endpoints it uses.

1. **`enrich_ip.py`** 

  - **Purpose**: Retrieves comprehensive threat intelligence for a given IP address, including geolocation (country, ASN, network), analysis verdict, detection counts, and GTI assessments.

  - **Key Features**:
    - **IP Report Retrieval**: Fetches detailed IP metadata and threat data, including geolocation, ASN details, analysis verdicts, and GTI assessments.
    - **Caching Mechanism**: Saves API responses to local cache to avoid redundant API calls and improve performance.
    - **Structured Output**: Presents verdict, location info, GTI assessment, and a deep link to the GTI web interface in a clean, readable format.
    - **Error Handling**: Gracefully handles network issues, API errors, and malformed responses.
    - **GTI GUI Deep Link**: Provides a clickable URL to view the IP's full threat intelligence report on the GTI web interface.

  - **API Endpoints Used**:
      - `/ip_addresses/{ip_address}`: Fetches the full threat intelligence report for the specified IP address.
  - **Use Case**: Assessing the risk of an IP address observed in network logs or alerts.

2. **`enrich_ip_with_relationship.py`**  

  - **Purpose**: Fetches only relationship data for an IP address, focusing on related threat entities.

  - **Key Features**:
      - **Relationship Data Extraction**: The script is configured to retrieve and present related threat intelligence entities from GTI. This includes:
          - **Collections**: IoC Collections of Indicators of Compromise are grouped together based on their observed usage in the wild in malicious campaigns or their association with specific malware families.
          - **Malware Families**: Curated information related to Malware Families.
          - **Related Threat Actors**: Threat Actors curated information exposed by our Google TI experts tracking them or by certain trusted partners and security researcher.
          - **Software Toolkits**: Curated information related to malicious Software or Toolkits used in threat campaigns.
          - **Campaigns**: Curated information related to threat Campaigns.
          - **Reports**: OSINT and curated threats related Reports. They could be crowdsourced references created by the cybersecurity industry, curated reports created by certain trusted partners and security researchers or our Google TI experts.
          - **Vulnerabilities**: Curated information of Vulnerabilities and exploitations coming from our Google TI experts analysis.
      - **API Integration**: The script uses the GTI API to fetch up-to-date intelligence related to the IP.
      - **Caching**: To reduce redundant API calls and improve performance, responses are cached locally. If a cache exists, the script loads from it instead of making a new API call.
      - **Structured Output**: The script prints the relationships in a readable format, showing the IDs and types of each related threat entity.

  - **API Endpoints Used**:
    - `/ip_addresses/{ip_address}/relationships/{relationship_type}`: Fetches relationship data for the specified IP address, where `relationship_type` includes `collections`, `malware_families`, `threat_actors`, `software_toolkits`, `campaigns`, `reports`, `vulnerabilities`, and `resolutions`.

  - **Use Case**: Understanding the broader threat context surrounding an IP address.

3. **`enrich_url.py`**  

  - **Purpose**: Retrieves threat intelligence for a specified URL, including verdict, detection counts, and GTI assessments.

  - **Key Features**:
      - **URL Report Retrieval**: Encodes the given URL as required by the GTI API, then fetches a full threat intelligence report for the resource.
      - **Caching Mechanism**: Stores responses locally to prevent redundant API calls and enhance performance. Cached reports are reused unless deleted manually.
      - **Structured Output**: Displays a clean summary of the analysis verdict (malicious or clean), malicious detection counts, and GTI assessments in a readable format.
      - **Error Handling**: Comprehensive handling of API errors, timeouts, malformed responses, and retry logic.
      - **GTI GUI Deep Link**: Provides a direct link to the GTI GUI for the analyzed URL, allowing for deeper investigation.

  - **API Endpoints Used**:
      - `/urls/{url_id}`: Fetches the full threat intelligence report for the specified URL (where `url_id` is the base64-encoded URL).

  - **Use Case**: Evaluating the safety of URLs in phishing or web traffic analysis.

4. **`enrich_url_with_relationship.py`**  

  - **Purpose**: Fetches only relationship data for a URL, focusing on linked threat entities.

  - **Key Features**:
      - **Relationship Data Extraction**: The script is configured to retrieve and present related threat intelligence entities from GTI. This includes:
          - **Collections**: IoC Collections of Indicators of Compromise are grouped together based on their observed usage in the wild in malicious campaigns or their association with specific malware families.
          - **Malware Families**: Curated information related to Malware Families.
          - **Related Threat Actors**: Threat Actors curated information exposed by our Google TI experts tracking them or by certain trusted partners and security researcher.
          - **Software Toolkits**: Curated information related to malicious Software or Toolkits used in threat campaigns.
          - **Campaigns**: Curated information related to threat Campaigns.
          - **Reports**: OSINT and curated threats related Reports. They could be crowdsourced references created by the cybersecurity industry, curated reports created by certain trusted partners and security researchers or our Google TI experts.
          - **Vulnerabilities**: Curated information of Vulnerabilities and exploitations coming from our Google TI experts analysis.
      - **API Integration**: The script uses the GTI API to fetch up-to-date intelligence related to the URL.
      - **Caching**: To reduce redundant API calls and improve performance, responses are cached locally. If a cache exists, the script loads from it instead of making a new API call.
      - **Structured Output**: The script prints the relationships in a readable format, showing the IDs and types of each related threat entity.

  - **API Endpoints Used**:
    - `/urls/{url_id}/relationships/{relationship_type}`: Fetches relationship data for the specified URL, where `relationship_type` includes `collections`, `malware_families`, `threat_actors`, `software_toolkits`, `campaigns`, `reports`, and `vulnerabilities`.

  - **Use Case**: Investigating URLs for connections to threat campaigns or actors.

5. **`enrich_domain.py`**  

  - **Purpose**: Retrieves threat intelligence for a domain, including verdict, detection stats, and GTI assessments.

  - **Key Features**:

      - **Domain Report Retrieval**: Sends a request to the GTI API for a given domain name and returns a full threat intelligence report including analysis statistics and assessments.
      - **Caching Mechanism**: Saves API responses locally to reduce redundant calls, improve performance, and provide offline accessibility. Reports are stored in a structured `cache/` directory.
      - **Structured Output**: Displays the verdict (malicious or clean), number of malicious detections, and GTI-specific assessments in a clean, human-readable format.
      - **Robust Error Handling**: Gracefully handles HTTP errors, connection issues, and parsing exceptions. Includes retry logic for transient failures such as rate limiting or timeouts.
      - **GTI GUI Deep Link**: Outputs a direct deep link to view the full domain intelligence report within the GTI web interface for extended manual analysis.

  - **API Endpoints Used**:
      - `/domains/{domain}`: Fetches the full threat intelligence report for the specified domain.

  - **Use Case**: Assessing the reputation of domains in malware or phishing campaigns.

6. **`enrich_domain_with_relationship.py`**  

  - **Purpose**: Fetches only relationship data for a domain, focusing on related threat entities.
  
  - **Key Features**:
      - **Relationship Data Extraction**: The script is configured to retrieve and present related threat intelligence entities from GTI. This includes:
          - **Collections**: IoC Collections of Indicators of Compromise are grouped together based on their observed usage in the wild in malicious campaigns or their association with specific malware families.
          - **Malware Families**: Curated information related to Malware Families.
          - **Related Threat Actors**: Threat Actors curated information exposed by our Google TI experts tracking them or by certain trusted partners and security researcher.
          - **Software Toolkits**: Curated information related to malicious Software or Toolkits used in threat campaigns.
          - **Campaigns**: Curated information related to threat Campaigns.
          - **Reports**: OSINT and curated threats related Reports. They could be crowdsourced references created by the cybersecurity industry, curated reports created by certain trusted partners and security researchers or our Google TI experts.
          - **Vulnerabilities**: Curated information of Vulnerabilities and exploitations coming from our Google TI experts analysis.
      - **API Integration**: The script uses the GTI API to fetch up-to-date intelligence related to the domain.
      - **Caching**: To reduce redundant API calls and improve performance, responses are cached locally. If a cache exists, the script loads from it instead of making a new API call.
      - **Structured Output**: The script prints the relationships in a readable format, showing the IDs and types of each related threat entity.

  - **API Endpoints Used**:
      - `/domains/{domain}/relationships/{relationship_type}`: Fetches relationship data for the specified domain, where `relationship_type` includes `collections`, `malware_families`, `threat_actors`, `software_toolkits`, `campaigns`, `reports`, `vulnerabilities`, and `resolutions`.

  - **Use Case**: Analyzing domains for connections to broader threat ecosystems.

7. **`enrich_file.py`**  

  - **Purpose**: Retrieves threat intelligence for a file hash (MD5, SHA-1, SHA-256), including verdict and detection counts.

  - **Key Features**:
      - **File Hash Report Retrieval**: Sends a request to the GTI API for a given SHA-256 (or MD5/SHA-1) file hash and retrieves a structured threat report.
      - **Caching Mechanism**: Implements local caching to avoid unnecessary repeated API calls, storing each response in a hash-named JSON file for later reuse.
      - **Structured Output**: Clearly displays the verdict (malicious or clean), detection count, and threat assessment in a user-friendly format.
      - **Robust Error Handling**: Detects and reports API errors, timeouts, permission issues, and retry logic.
      - **GTI GUI Deep Link**: Provides a clickable URL to view the file's full threat intelligence report on the GTI web interface.

  - **API Endpoints Used**:
      - `/files/{file_hash}`: Fetches the full threat intelligence report for the specified file hash.

  - **Use Case**: Investigating suspicious files in malware incidents.

8. **`enrich_file_with_relationship_and_behaviour.py`**  

  - **Purpose**: Fetches comprehensive threat intelligence for a file hash, including relationships, sandbox behavior, and MITRE ATT&CK mappings.

  - **Key Features**:
      - **Relationship Data Extraction**: The script is configured to retrieve and present related threat intelligence entities. This includes:
          - **Collections**: IoC Collections of Indicators of Compromise are grouped together based on their observed usage in the wild in malicious campaigns or their association with specific malware families.
          - **Malware Families**: Curated information related to Malware Families.
          - **Related Threat Actors**: Threat Actors curated information exposed by our Google TI experts tracking them or by certain trusted partners and security researcher.
          - **Software Toolkits**: Curated information related to malicious Software or Toolkits used in threat campaigns.
          - **Campaigns**: Curated information related to threat Campaigns.
          - **Reports**: OSINT and curated threats related Reports. They could be crowdsourced references created by the cybersecurity industry, curated reports created by certain trusted partners and security researchers or our Google TI experts.
          - **Vulnerabilities**: Curated information of Vulnerabilities and exploitations coming from our Google TI experts analysis.
      - **API Integration**: The script uses the GTI API to fetch up-to-date intelligence related to the file.
      - **Caching**: To reduce redundant API calls and improve performance, responses are cached locally. If a cache exists, the script loads from it instead of making a new API call.
      - **MITRE ATT&CK Enrichment**: Leverages sandbox execution analysis to identify associated MITRE tactics and techniques. This provides analysts with insights into how the file behaves in real-world scenarios, mapped directly to the MITRE ATT&CK framework.
      - **Sandbox Behavior Analysis**: Displays dynamic behavioral observations from sandbox analysis, including behavioral patterns, toolkits observed, and behavioral identifiers linked to the file.
      - **Structured Output**: The script prints the relationships in a readable format, showing the IDs and types of each related threat entity.

  - **API Endpoints Used**:
      - `/files/{file_hash}/relationships/{relationship_type}`: Fetches relationship data for the specified file hash, where `relationship_type` includes `collections`, `malware_families`, `threat_actors`, `software_toolkits`, `campaigns`, `reports`, and `vulnerabilities`.
      - `/files/{file_hash}/behaviours`: Fetches sandbox behavior data for the specified file hash.
      - `/files/{file_hash}/attack_tids`: Fetches MITRE ATT&CK mappings for the specified file hash.

  - **Use Case**: Deep analysis of malware samples to understand behavior and threat associations.

## How to Run the Scripts

Follow these steps to set up and run the scripts:

### 1. Install Dependencies

Ensure you have the required Python libraries installed. Run the following command in your terminal or command prompt:

```bash
pip install -r requirements.txt
```

### 2. Configure API Credentials

All scripts require a valid GTI API key and product header. Replace the placeholders in each script:

```python
GTI_API_KEY = "YOUR_API_KEY"
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
```
### 3. Run a Script
Navigate to the `/automatic_and_manual_enrichment` directory and execute the desired script using Python from the command line.

  - For Domain Enrichment:  
    ```bash
    python enrich_domain.py
    ```

  - For Domain Enrichment With Relationship:  
    ```bash
    python enrich_domain_with_relationship.py
    ```

### 4. Customize Inputs

Modify the default inputs in each script (e.g., domain, file hash, URL) as needed. Refer to inline comments for guidance on required parameters and formats.

### 5. Review Output

Each script formats the output in a human-readable JSON structure, clearly highlighting key details such as verdicts, GTI assessments, and relationships. You can view the results directly in the console, or modify the script to save the output to a file if needed.

Additionally, example outputs are provided in the `/automatic_and_manual_enrichment` directory. For instance, the output of the `enrich_ip.py` script can be found in the `enrich_ip_output.md` file. Similar output files are provided for other scripts in the same directory, offering example results and detailed explanations of the JSON structure.


## Additional Notes

  - **Script Documentation**: Each script contains detailed comments explaining its functionality, parameters, and error handling.
  - **GTI API Documentation**: For endpoint details and query syntax, refer to the official GTI Documentation.
      - [IP Enrichment Documentation](https://gtidocs.virustotal.com/reference/ip-info)
      - [Domain Enrichment Documentation](https://gtidocs.virustotal.com/reference/domain-info)
      - [File Enrichment Documentation](https://gtidocs.virustotal.com/reference/file-info)
      - [URL Enrichment Documentation](https://gtidocs.virustotal.com/reference/url-info)
      - [Mitre Attack Data Documentation](https://gtidocs.virustotal.com/reference/get-a-summary-of-all-mitre-attck-techniques-observed-in-a-file)
      - [Sandbox Behaviour Documentation](https://gtidocs.virustotal.com/reference/get-all-behavior-reports-for-a-file)

  - **Troubleshooting**: Refer to `troubleshooting.md` in the `/docs` folder for help with common issues like API errors, rate limits, or invalid inputs.
  - **API Quota Management**: Both scripts include retry logic for HTTP 429 (rate limit) and 5xx errors. Monitor API usage to stay within your quota, especially during frequent polling.
  - **Error Handling**: The scripts handle network failures, invalid responses, and parsing errors, providing clear feedback and retry suggestions. Check console output for error details.
