# Google Threat Intelligence (GTI) Threat List and IOC Stream Ingestion Scripts

This repository contains Python scripts designed to interface with the Google Threat Intelligence (GTI) API to fetch and process curated threat lists and real-time Indicator of Compromise (IOC) streams. These scripts enable security analysts, threat researchers, and developers to automate the ingestion of high-confidence IOCs for use in watchlists, blocklists, detection rules, or trend analysis, supporting proactive threat hunting and defense strategies.

## Overview
The scripts streamline the retrieval and processing of threat intelligence data by fetching curated threat lists and near-real-time IOC streams from the GTI API. They are designed to support security operations by providing actionable insights into emerging threats, with structured outputs for easy integration into security platforms. Each script includes robust error handling, retry logic for transient failures, and pagination support for efficient data retrieval.

## Threat Lists Ingestion
  - **Objective**: Enable the automated, periodic fetching of high-confidence IOCs from GTI's curated threat lists for use in watchlists, blocklists, detection rules, or to calculate trends.

  - **Key Implementation Points**:
      - Implement a reliable scheduling mechanism to pull updates periodically (e.g., hourly), only fetching new IOCs since the last run to conserve bandwidth and API quota.
      - Properly parse and map the ingested IOCs to the correct fields within your platform (e.g., IP, domain) and apply appropriate tags for context.
      - Handle large datasets efficiently, ensuring minimal processing overhead for high-volume threat lists.

  - **Relevant API Calls**:
      - `/intelligence/threat_lists/{list_name}`: Fetch the latest version of a specific threat list (e.g., ransomware, cryptominer).
      - `/intelligence/threat_lists/{list_name}/hourly/{timestamp}`: Fetch an hourly snapshot of a threat list for a specified category and time (format: YYYYMMDDHH).

  - **User Experience (UX) Best Practice**:
      - Provide a clear interface where users can see which lists are enabled, the number of IOCs ingested from each, and the timestamp of the last successful sync.

  - **Configuration Tip**:
      - Allow users to select which specific threat list categories they want to ingest and set the synchronization frequency to balance API quota and freshness of data.

  - [**Best Practices Guide**](https://docs.google.com/document/d/1foYWa5FnlwtYBIo63YIZU5AOInI7UsNdrn9g0ty25Ag/edit?resourcekey=0-SIeMz9ALACxg0qGd75Jm4g&tab=t.0#heading=h.oipgoq9zaol4)


## IOC Stream Ingestion
  - **Objective**: Ingest a near-real-time stream of newly discovered IOCs from GTI to enable immediate detection and blocking of emerging threats.

  - **Key Implementation Points**:
      - Define a polling mechanism to fetch IOC data periodically at set intervals, ensuring new IOCs are retrieved efficiently using pagination cursors.
      - Implement robust error handling and reconnection logic to manage network interruptions and API rate limits.
      - Process the high volume of incoming data efficiently, filtering out irrelevant IOCs before they are stored or acted upon.

  - **Relevant API Calls**:
      - `/ioc_stream`: Fetch the latest IOC stream objects, with pagination support via a cursor parameter.

  - **User Experience (UX) Best Practice**:
      - Display live statistics for the stream, including connection status, IOCs ingested per minute, and any errors, to provide confidence in its operation.

  - **Configuration Tip**:
      - Configure polling intervals to balance real-time needs with API quota limits, and allow users to filter IOCs by type or source for relevance.

  - [**Best Practices Guide**](https://docs.google.com/document/d/1foYWa5FnlwtYBIo63YIZU5AOInI7UsNdrn9g0ty25Ag/edit?resourcekey=0-SIeMz9ALACxg0qGd75Jm4g&tab=t.0#heading=h.3lswyz08fi)

## Key Features
  - **Threat List Retrieval**: Fetches curated threat lists for categories like ransomware, cryptominers, phishing, and more, supporting both latest and hourly snapshots.
  - **IOC Stream Retrieval**: Provides access to a real-time, curated feed of IOCs, enabling immediate threat detection and response.
  - **Continuous Polling**: Supports periodic polling of IOC streams and threat lists with configurable intervals and retry logic for reliable data ingestion.
  - **Pagination Support**: Automatically manages pagination cursors to ensure efficient retrieval of new IOCs without duplicates.
  - **Structured Output**: Presents IOC counts, verdicts, threat scores, and full JSON responses in a human-readable format for quick analysis.
  - **Robust Error Handling**: Gracefully handles HTTP errors, rate limits, network issues, and parsing exceptions, with retry suggestions for transient failures.
  - **Threat Intelligence Curation**: Enables security professionals to build custom threat feeds by filtering and mapping IOCs to platform-specific fields.

## IOC Stream Ingestion Use Cases
  - **SIEM**:
      - **Real-Time Threat Detection**: Correlates live IOCs (e.g., malicious IPs) with logs to detect breaches instantly.
      - **Incident Enrichment**: Enriches alerts with real-time IOC context (e.g., linking a hash to malware).

  - **SOAR**:
      - **Automated Threat Blocking**: Updates firewalls/EDR with live IOCs to block threats.
      - **Dynamic Incident Response**: Triggers playbooks to isolate endpoints or reset credentials based on new IOCs.

## Threat List Ingestion Use Cases
  - **SIEM**:
      - **Targeted Threat Monitoring**: Detects specific threats (e.g., ransomware hashes) using curated lists.
      - **Compliance Reporting**: Generates reports on threat monitoring for regulatory compliance.

  - **SOAR**:
      - **Automated Enrichment**: Adds context to incidents using curated threat list data (e.g., phishing campaign details).
      - **Proactive Threat Hunting**: Automates searches for curated IOCs to uncover hidden threats.

## Scripts Overview
The repository includes the following scripts, each tailored to a specific threat intelligence ingestion goal, with details on their key features and GTI API endpoints used.

### `ingest_ioc_stream.py`
  - **Purpose**: Fetches and displays the latest IOC stream objects from the GTI API, providing real-time threat intelligence.

  - **Key Features**:
      - **IOC Stream Retrieval**: Retrieves the most recent IOC stream data from the GTI API endpoint.

      - **Error Handling**: Implements robust error detection and reporting, including retries for rate limits and network issues.

      - **Data Presentation**: Outputs a concise summary of new IOCs, showing up to three entries for quick review.

  - **API Endpoints Used**:
      - `/ioc_stream`: Fetches the latest IOC stream objects

  - **Use Case**: Enabling immediate detection and blocking of emerging threats through real-time IOC ingestion.

### `ingest_ioc_stream_with_polling.py`
  - **Purpose**: Fetches and processes IOC stream objects from the GTI API with continuous polling, enabling real-time monitoring of emerging threats.

  - **Key Features**:
      - **IOC Stream Retrieval**: Fetches IOC stream objects from the GTI API, allowing users to access a real-time, curated feed of threats.

      - **Continuous Polling**: Includes a function to poll the IOC stream endpoint over a specified number of iterations and at a defined interval, enabling continuous monitoring.

      - **Pagination Support**: Manages pagination automatically using a cursor, ensuring that each poll fetches only new objects since the last request, which is crucial for efficient data retrieval.

      - **Threat Intelligence Curation**: Allows security professionals to build and curate custom threat feeds, making this script a valuable tool for threat hunting and proactive defense strategies.

  - **API Endpoints Used**:
      - `/ioc_stream`: Fetches the latest IOC stream objects, with optional cursor for pagination.

  - **Use Case**: Continuous monitoring of IOC streams for real-time threat detection and response in security operations.

### `ingest_threat_list.py`
  - **Purpose**: Fetches and displays curated threat lists from the GTI API based on a specified category, supporting both latest and hourly data.

  - **Key Features**:
      - **Threat List Retrieval**: Fetches the latest version of a specific threat list from the GTI API based on a user-provided name.

      - **Support for Multiple Lists**: Retrieves IOCs for a wide range of threat categories, including:
          - Ransomware
          - Malicious Network Infrastructure
          - Malware
          - Threat Actors
          - Daily Top Trending
          - Mobile
          - OS X
          - Linux
          - Internet of Things (IoT)
          - Cryptominers
          - Phishing
          - First Stage Delivery Vectors
          - Vulnerability Weaponization
          - Infostealers

      - **Structured Output**: Retrieves the raw JSON response and prints a summary of the threat list, including the total number of entries and the first few IOCs, for quick analysis.

      - **Error Handling**: Includes basic error handling to gracefully manage API request failures.

  - **API Endpoints Used**:
    - `/intelligence/threat_lists/{list_name}`: Fetches the latest threat list for a specified category.
    - `/intelligence/threat_lists/{list_name}/hourly/{timestamp}`: Fetches an hourly snapshot of a threat list.

  - **Use Case**: Automating the ingestion of high-confidence IOCs for watchlists, blocklists, or trend analysis in security operations.

### `ingest_threat_list_with_polling.py`
  - **Purpose**: Fetches and processes curated threat lists from the GTI API with continuous polling, supporting both latest and hourly data for specified categories.

  - **Key Features**:
      - **Threat List Retrieval**: Fetches the latest version of a specific threat list from the GTI API based on a user-provided name.

      - **Support for Multiple Lists**: Retrieves IOCs for a wide range of threat categories, including:
          - Ransomware
          - Malicious Network Infrastructure
          - Malware
          - Threat Actors
          - Daily Top Trending
          - Mobile
          - OS X
          - Linux
          - Internet of Things (IoT)
          - Cryptominers
          - Phishing
          - First Stage Delivery Vectors
          - Vulnerability Weaponization
          - Infostealers

      - **Hourly Threat List Retrieval**: Fetches hourly IOC threat lists for a specified category from the GTI API.

      - **Robust Error Handling**: Handles HTTP errors, rate limits, network issues, and parsing exceptions gracefully, with retry logic for transient failures.

  - **API Endpoints Used**:
      - `/intelligence/threat_lists/{list_name}`: Fetches the latest threat list for a specified category.
      - `/intelligence/threat_lists/{list_name}/hourly/{timestamp}`: Fetches an hourly snapshot of a threat list.

  - **Use Case**: Continuous monitoring of curated threat lists for automated ingestion into security systems, enabling timely updates to watchlists and detection rules.


## Threat List Types
The following table lists the threat list categories supported by the GTI API, including their identifiers, supported entities, license requirements, and descriptions. Use these threat list IDs in `ingest_threat_list.py` and `ingest_threat_list_with_polling.py` to fetch specific categories.

| Category Name | Threat List ID | Entities Supported | License Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| Ransomware | `ransomware` | Files | All | IOCs categorized as Ransomware by our security engine partners or Google TI experts. |
| Malicious Network Infrastructure | `malicious-network-infrastructure` | URLs, Domains, IP Addresses | All | Network-related IOCs associated with Malware Infrastructure by Google TI experts. |
| Malware | `malware` | Files, URLs, Domains, IP Addresses | Enterprise, Enterprise Plus | IOCs identified and classified as malware by Google TI specialists. |
| Threat Actor | `threat-actor` | Files, URLs, Domains, IP Addresses | Enterprise, Enterprise Plus | IOCs linked to specific Threat Actors by Google TI experts. |
| Daily Top Trending | `trending` | Files, URLs, Domains, IP Addresses | Enterprise, Enterprise Plus | Top trending IOCs based on daily lookups and relevance. |
| Mobile | `mobile` | Files | Enterprise Plus | iOS and Android files identified as malware by security engine partners. |
| OS X | `osx` | Files | Enterprise Plus | OS X files identified as malware by security engine partners. |
| Linux | `linux` | Files | Enterprise Plus | Linux files identified as malware by security engine partners. |
| Internet of Things | `iot` | Files | Enterprise Plus | IoT files identified as malware by security engine partners. |
| Cryptominers | `cryptominer` | Files, URLs, Domains, IP Addresses | Enterprise Plus | IOCs classified as Miners by security engine partners. |
| Phishing | `phishing` | URLs, Domains, IP Addresses | Enterprise Plus | Network-related IOCs classified as Phishing by security engine partners. |
| First Stage Delivery Vectors | `first-stage-delivery-vectors` | Files | Enterprise Plus | Email attachments and files served by URLs, identified as malware by security engine partners. |
| Vulnerability Weaponization | `vulnerability-weaponization` | Files, URLs, Domains, IP Addresses | Enterprise Plus | IOCs related to vulnerability exploitation by security engine partners or Google TI experts. |
| Infostealers | `infostealer` | Files | Enterprise Plus | Files categorized as Infostealers by security engine partners or Google TI experts. |


## How to Run the Scripts
Follow these steps to set up and run the scripts:

### 1.  Install Dependencies
Ensure you have the required Python libraries installed. Run the following command in your terminal or command prompt:

```bash
pip install -r requirements.txt
```

### 2.  Configure API Credentials
All scripts require a valid GTI API key and product header. Replace the placeholders in each script:

```python
GTI_API_KEY = "YOUR_API_KEY"
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
```

### 3.  Run a Script
Execute any script using Python from the command line. Navigate to the `threat_list_and_ioc_stream_ingestion` directory and run:

  - For Threat List Ingestion:
    ```bash
    python python ingest_threat_list.py
    ```

  - For IOC Stream Ingestion:
    ```bash
    python python ingest_ioc_stream.py
    ```

### 4.  Customize Inputs
Modify the default inputs in each script (e.g., threat list name, polling interval) as needed. Refer to inline comments for guidance on required parameters and formats. For example, in `ingest_threat_list.py`, change `list_name = "ransomware"` to another category like `phishing`.

### 5.  Review Output
Each script generates detailed threat intelligence results, including IOC counts and summary tables. Example outputs are available in the `/threat_list_and_ioc_stream_ingestion` directory. For instance, the output of the `ingest_ioc_stream.py` script can be found in the `ingest_ioc_stream_output.md` file. Similar output files are provided for other scripts in the same directory, offering example results and detailed explanations of the JSON structure.


## Additional Notes
  - **Polling Configuration**: For `ingest_ioc_stream_with_polling.py` and `ingest_threat_list_with_polling.py`, configure polling intervals (e.g., every 60 seconds) to balance real-time needs with API quota limits. These scripts support pagination cursors to avoid duplicate IOCs.

  - **Threat List Categories**: `ingest_threat_list.py` and `ingest_threat_list_with_polling.py` support multiple categories (e.g., ransomware, cryptominers, phishing). Ensure the selected category matches your use case to avoid irrelevant data. See the "Threat List Types" section for details.

  - **API Quota Management**: All scripts include retry logic for HTTP 429 (rate limit) and 5xx errors. Monitor API usage to stay within your quota, especially for frequent polling.

  - **Error Handling**: Scripts handle network failures, invalid responses, and parsing errors, providing clear feedback and retry suggestions. Check console output for error details.

  - **Output Storage**: By default, outputs are printed to the console. Modify the scripts to save JSON responses to files for integration with other systems (e.g., SIEM).

  - **Script Documentation**: Each script contains detailed comments explaining its functionality, parameters, and error handling.

  - **GTI API Documentation**: For endpoint details and query syntax, refer to the official GTI Documentation.
      - [Threat List Documentation](https://gtidocs.virustotal.com/reference/threat-list-overview)
      - [IOC Stream Documentation](https://gtidocs.virustotal.com/reference/get-objects-from-the-ioc-stream)

  - **Troubleshooting**: Refer to `troubleshooting.md` in the `/docs` folder for help with common issues like API errors, rate limits, or invalid inputs.

