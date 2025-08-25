# Google Threat Intelligence (GTI) Integration Scripts and Workflows

This repository contains a comprehensive collection of Python scripts and workflows designed to integrate Google Threat Intelligence (GTI) with various security platforms, including Security Orchestration, Automation, and Response (SOAR) systems and Security Information and Event Management (SIEM) platforms. These resources empower security analysts, incident responders, and threat researchers to automate threat intelligence tasks, streamline security operations, and proactively manage risks by leveraging GTI's extensive threat data for actionable insights.

## Overview

The repository provides modular scripts and workflows for key GTI functionalities, including Attack Surface Management (ASM), Digital Threat Monitoring (DTM), File and URL Scanning, Vulnerability Intelligence, Threat List and IOC Stream Ingestion, Manual and Automatic Enrichment, and Widget Embedding. Each module is crafted to interface seamlessly with the GTI API, featuring robust error handling, structured JSON outputs, and detailed documentation to ensure smooth integration with security platforms. The goal is to reduce manual intervention, enhance response times, and provide security teams with a unified view of their threat landscape.

## Repository Structure

The repository is organized into the following directories, each containing specific scripts or workflows with their respective `README.md` files for detailed instructions:

- `/docs`: Contains troubleshooting guides (`troubleshooting.md`) for common issues like API errors, rate limits, or configuration problems.
- `/example`: Core modules with scripts and workflows:
    - **Automatic and Manual Enrichment**: Scripts for enriching Indicators of Compromise (IOCs) such as IPs, domains, URLs, and file hashes with GTI data, supporting both manual and automated workflows.
    - **File and URL Scanning**: Scripts for private and public scanning of files and URLs, including polling for analysis completion and detailed report retrieval.
    - **Vulnerability Intelligence**: Script for retrieving curated CVE data, risk ratings, exploitation trends, and threat actor associations.
    - **Threat List and IOC Stream Ingestion**: Scripts for fetching curated threat lists and real-time IOC streams for watchlists, blocklists, and detection rules.
    - **Workflow/Playbook**: Example workflows for SOAR platforms, including a sample for fetching IOC stream notifications with webhook integration.
    - **GTI Widget**: Script for embedding VirusTotal Augment Widgets to visualize IOC threat context interactively.
    - **ASM**: Scripts for retrieving and polling Attack Surface Management issues to identify vulnerabilities, misconfigurations, and exposed assets.
    - **DTM**: Scripts for fetching and polling Digital Threat Monitoring alerts to track threats like phishing campaigns, brand impersonation, or data leaks.

- `requirements.txt`: Lists Python dependencies required to run the scripts.

## Key Features

- **Comprehensive Automation**: Automates repetitive tasks such as IOC enrichment, file scanning, alert ingestion, and vulnerability prioritization to minimize manual effort.
- **GTI Data Integration**: Leverages GTI's rich threat intelligence for critical use cases like threat hunting, incident response, vulnerability management, and attack surface monitoring.
- **Out-of-the-Box Solutions**: Provides ready-to-use scripts with clear documentation for rapid deployment and customization.
- **Robust Error Handling**: Includes retry logic for HTTP 429 (rate limit) and 5xx errors, ensuring reliable operation under varying conditions.
- **Customizable Outputs**: Generates structured JSON outputs, easily integrated with SIEMs, SOARs, or custom dashboards for further analysis.
- **User Experience Optimization**: Features intuitive script designs with clear naming, logical grouping, and detailed comments for ease of use and discoverability.
- **Scalability**: Supports pagination and efficient data handling for large datasets, ensuring performance in high-volume environments.
- **Cross-Platform Compatibility**: Designed to integrate with various platforms, including Splunk SOAR, IBM SOAR, Rapid7 InsightConnect, and other security tools.


## Getting Started

### 1. Install Dependencies

- Ensure **Python 3.8+** is installed on your system.
- Install required packages by running:

```bash
pip install -r requirements.txt
```
### 2. Configure API Credentials

- Obtain a valid GTI API key from the GTI platform.
- Configure the API key and product header in each script (e.g., replace `GTI_API_KEY = "YOUR_API_KEY"` and `X_TOOL_HEADER = "YOUR_PRODUCT_NAME"`).
- Ensure proper configuration to avoid authentication errors during API calls.

### 3. Explore Modules

- Navigate to the desired module directory (e.g., `/example/ASM` or `/example/Workflow-Playbook`).
- Refer to the module-specific `README.md` for detailed setup, usage, and customization instructions.

### 4. Run Scripts 

- Execute Python scripts from the command line (e.g., python ingest_asm_issues.py).
- For SOAR workflows, import the provided playbooks into your platform and follow the steps outlined in the respective README.md.
- Example command for running a script:

```bash
cd example/ASM
python ingest_asm_issues.py
```

### 5. Run Scripts 

- Each module includes example outputs in markdown files (e.g., `ingest_asm_issues_output.md`) within its directory, detailing JSON structures and sample results.
- Outputs can be saved to files (e.g., JSON, CSV) for integration with other systems by modifying the scripts as needed.

## Module-Specific Documentation
For detailed instructions on each module, refer to the respective README.md files in the following directories:

- `/example/Automatic and Manual Enrichment/README.md`: Guides for enriching IOCs with GTI data.
- `/example/File and URL Scanning/README.md`: Instructions for scanning files and URLs in private or public modes.
- `/example/Vulnerability Intelligence/README.md`: Details on retrieving and prioritizing CVE data.
- `/example/Threat List and IOC Stream Ingestion/README.md`: Steps for ingesting threat lists and IOC streams.
- `/example/Workflow-Playbook/README.md`: Instructions for GTI workflows in SOAR platforms.
- `/example/GTI Widget/README.md`: Guide for embedding VirusTotal Augment Widgets.
- `/example/ASM/README.md`: Instructions for managing attack surface issues.
- `/example/DTM/README.md`: Steps for monitoring digital threats with DTM alerts.
- `/testcases`: Contains test cases to validate GTI Dev Kit script functionality, ensuring reliability and accuracy of enrichment, ingestion, scanning, retrieval, and intelligence features, using pytest and mock objects for API and file operation simulation.

## Best Practices

- **API Key Security**: Store GTI API keys securely (e.g., in environment variables or a secrets manager) to prevent unauthorized access.
- **Quota Management**: Monitor API usage to stay within GTI quotas, especially for polling scripts. Adjust polling intervals to balance data freshness and quota limits.
- **Error Logging**: Enable logging in scripts to capture detailed error messages for troubleshooting. Refer to console outputs or create log files as needed.
- **Customization**: Tailor query parameters, filters, and output formats to align with your organization's specific needs and workflows.
- **Testing**: Test scripts and workflows in a sandbox environment before deploying to production to ensure compatibility and performance.
- **Documentation**: Leverage the detailed comments in each script and the module-specific `README.md` files to understand functionality and customization options. 
- [**Google Threat Intelligence: A Best Practices Guide**](https://docs.google.com/document/d/1foYWa5FnlwtYBIo63YIZU5AOInI7UsNdrn9g0ty25Ag/edit?resourcekey=0-SIeMz9ALACxg0qGd75Jm4g&tab=t.0#heading=h.iu05rh2fex9i)

## GTI API Reference Table

| **Use Case**                | **Script**                        | **Primary API Endpoint(s)**                                                                 |
|-----------------------------|-----------------------------------|---------------------------------------------------------------------------------------------|
| Domain Enrichment           | `enrich_domain.py`                | `GET /api/v3/domains/{domain}`                                                              |
| File Enrichment             | `enrich_file.py`                  | `GET /api/v3/files/{file_hash}`,<br>`GET /api/v3/files/{file_hash}/behaviour_mitre_trees`   |
| IP Enrichment               | `enrich_ip.py`                    | `GET /api/v3/ip_address/{ip_address}`                                                       |
| URL Enrichment              | `enrich_url.py`                   | `GET /api/v3/urls/{url_id}`                                                                |
| ASM Ingestion               | `ingest_asm_issues.py`            | `GET /api/v3/asm/search/issues/{search_string}`                                             |
| DTM Ingestion               | `ingest_dtm_alerts.py`            | `GET /api/v3/dtm/alerts`                                                                   |
| IOC Stream Ingestion        | `ingest_ioc_stream.py`            | `GET /api/v3/ioc_stream`                                                                   |
| Threat List Ingestion       | `ingest_threat_list.py`           | `GET /api/v3/threat_lists/{category}/latest`                                                |
| Private File Scanning       | `private_scanning/scan_file.py`   | `POST /api/v3/private/files`,<br>`GET /api/v3/private/analyses/{analysis_id}`,<br>`GET /api/v3/private/files/{file_hash}` |
| Private URL Scanning        | `private_scanning/scan_url.py`    | `POST /api/v3/private/urls`,<br>`GET /api/v3/private/analyses/{analysis_id}`,<br>`GET /api/v3/private/urls/{url_id}` |
| Public File Scanning        | `public_scanning/scan_file.py`    | `POST /api/v3/files`,<br>`GET /api/v3/analyses/{analysis_id}`,<br>`GET /api/v3/files/{file_hash}` |
| Public URL Scanning         | `public_scanning/scan_url.py`     | `POST /api/v3/urls`,<br>`GET /api/v3/analyses/{analysis_id}`,<br>`GET /api/v3/urls/{url_id}` |
| GTI Widget                  | `widget.py`                       | `GET /widget/url/{ioc}`                                                              |
| Vulnerability Intelligence  | `vulnerability.py`                | `GET /collections`                                                              |


## Additional Notes

- **API Quota Management**: All scripts include retry logic for HTTP 429 (rate limit) and 5xx errors. Monitor API usage to stay within your GTI quota, particularly for polling scripts or high-frequency queries.
- **Error Handling**: Scripts handle network failures, invalid responses, and parsing errors, providing clear feedback and retry suggestions. Check console output for detailed error information.
- **Output Storage**: By default, outputs are printed to the console. Modify scripts to save data to files (e.g., JSON, CSV) or integrate directly with SIEMs, SOARs, or databases.
- **GTI API Documentation**: Refer to the official GTI Documentation for endpoint details, query syntax, and API limitations.
- **Troubleshooting**: Consult `/docs/troubleshooting.md` for help with common issues like API errors, rate limits, or invalid inputs. Create additional troubleshooting guides as needed.
- **Integration Tips**: Use script outputs to create incidents, update asset inventories, or trigger alerts in your security platform. Leverage webhooks or API endpoints to sync data back to GTI (e.g., for status updates).
- **Widget Customization**: For GTI Widget integration, adjust parameters like colors (`bd1`, `bg1`, `bg2`, `fg1`) to match your platform’s theme for a seamless user experience.
- **Performance Optimization**: For high-volume data (e.g., threat lists or IOC streams), use pagination and incremental fetching to minimize processing overhead and conserve API quota.