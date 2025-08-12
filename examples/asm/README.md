# Google Threat Intelligence (GTI) Attack Surface Management (ASM) Issues Script

This repository contains Python scripts designed to interface with the Google Threat Intelligence (GTI) API to search for Attack Surface Management (ASM) issues. ASM simulates an attacker's viewpoint to help organizations proactively identify vulnerabilities, misconfigurations, and their potential impact on digital assets. These scripts enable security teams to discover and assess security risks across their external-facing assets efficiently.

## Overview

The `ingest_asm_issues.py` and `ingest_asm_issues_with_polling.py` scripts streamline the retrieval of ASM issues from the GTI API, providing structured JSON output for easy analysis. They support flexible query strings (e.g., filtering by severity or asset type) and robust error handling for reliable operation. The polling script adds periodic querying to keep issue data current, making it ideal for continuous monitoring. These scripts facilitate integration with security platforms to create incidents, correlate assets, and synchronize updates with the GTI platform.

## ASM Support
  - **Objective**: Integrate ASM findings from GTI to help users discover, inventory, and assess the security posture of their external-facing assets.

  - **Key Implementation Points**:
    - Fetch and display ASM data, including newly discovered domains, open ports, software vulnerabilities, and security misconfigurations.
    - Correlate ASM assets with the organization's internal asset inventory to create a unified view of the attack surface.
    - Automatically create corresponding incidents, cases, or alerts in the host platform based on the ingested ASM data.
    - Send ASM issues updates, such as status changes, back to the GTI platform to keep data in sync.

  - **Relevant API Calls**:
    - `/asm/search/issues/{query_string}`: Searches for ASM issues based on a user-provided query string.

  - **User Experience (UX) Best Practice**:
    - If applicable, present ASM findings in a dedicated dashboard that highlights the most critical risks and provides clear, actionable remediation guidance.

  - **Configuration Tip**:
    - Allow users to configure the specific ASM project within the integration settings to ensure they are pulling data from the correct attack surface. Customize query strings to focus on high-priority issues (e.g., `severity:5`).

  - [**Best Practices Guide**](https://docs.google.com/document/d/1foYWa5FnlwtYBIo63YIZU5AOInI7UsNdrn9g0ty25Ag/edit?resourcekey=0-SIeMz9ALACxg0qGd75Jm4g&tab=t.0#heading=h.66xy5mhxqbaf)

## Key Features
  - **ASM Issue Search**: Queries the GTI ASM issues endpoint with a user-provided query string to filter issues (e.g., by severity or asset type).

  - **Vulnerability Identification**: Pinpoints critical vulnerabilities and misconfigurations across the attack surface that could be exploited by attackers.

  - **Structured Output**: Extracts and presents issue data in formatted JSON for clear, actionable insights.

  - **Error Handling**: Implements robust handling of HTTP errors, rate limits, and network issues, with retry logic for transient failures.

  - **Polling Mechanism**: Enables periodic polling with configurable intervals to keep issue data current (in `ingest_asm_issues_with_polling.py`).

  - **Scalable Integration**: Handles high-volume ASM data efficiently, supporting correlation with internal assets and status synchronization.

## Use Case: Mapping ASM Issues to SOAR Incidents
- Automatically convert ASM issues (e.g., misconfigured domains, exposed APIs) into SOAR incidents.
- Enables SOC analysts to:
  - Assess external exposures from an adversary’s perspective.
  - Investigate using automated playbooks.
  - Mitigate risks to reduce attack surface.

## Scripts Overview
The repository includes the following scripts, tailored to search and process ASM issues from the GTI API for vulnerability management and analysis.

#### `ingest_asm_issues.py`
  - **Purpose**: Searches for ASM issues with a user-provided query string (e.g., `severity:5`), displaying issues in a formatted JSON output.

  - **Key Features**:
      - **ASM Issue Search**: Queries the `/asm/search/issues/{query_string}` endpoint with filters like severity or time.
      - **Vulnerability Identification**: Identifies critical vulnerabilities and misconfigurations across external assets.
      - **Structured Output**: Presents issue data in a clear, formatted JSON structure.
      - **Error Handling**: Manages API request failures (e.g., network issues, HTTP errors) with retry suggestions.

  - **API Endpoints Used**:
      - `/asm/search/issues/{query_string}`: Searches for ASM issues based on query parameters.

  - **Use Case**: One-time retrieval of ASM issues for initial vulnerability assessment or manual review.

#### `ingest_asm_issues_with_polling.py`
  - **Purpose**: Searches for ASM issues with a query string and periodic polling, displaying issues per poll in a formatted JSON output.

  - **Key Features**:
      - **ASM Issue Search**: Queries the `/asm/search/issues/{query_string}` endpoint with configurable query strings.
      - **Vulnerability Identification**: Identifies critical vulnerabilities and misconfigurations across external assets.
      - **Structured Output**: Presents issue data in formatted JSON for quick analysis.
      - **Polling Mechanism**: Polls the API at configurable intervals for continuous monitoring.
      - **Error Handling**: Manages HTTP errors, rate limits, and network issues with retry logic.

  - **API Endpoints Used**:
      - `/asm/search/issues/{query_string}`: Searches for ASM issues with pagination support.

  - **Use Case**: Continuous monitoring of ASM issues for real-time vulnerability detection and integration with security platforms.


## Input Parameters
**`historical_time`**

  - **Description**: Time from when issues should be retrieved (must be within the last 5 days).
  - **Example**: `2025-08-01T00:00:00Z`

**`search_string`**

  - **Description**: Provide the search string for which issues should be retrieved. This can include filters such as severity, asset type, etc.
  - **Example**: `severity:5 asset_type:web`

## How to Run the Scripts
Follow these steps to set up and run the scripts:

### 1.  Install Dependencies
Ensure you have the required Python libraries installed. Run the following command in your terminal or command prompt:

```bash
pip install -r requirements.txt
```

### 2.  Configure API Credentials
Both scripts require a valid GTI API key and product header. Replace the placeholders in each script:

```python
GTI_API_KEY = "YOUR_API_KEY"
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
```

### 3.  Run the Scripts
Navigate to the `asm` directory and execute the desired script using Python from the command line.

  - For one-time issue retrieval:
    ```bash
    python ingest_asm_issues.py
    ```

  - For continuous polling:
    ```bash
    python ingest_asm_issues_with_polling.py
    ```

### 4.  Customize Inputs

Modify the query string in the scripts (e.g., `query_string` in `main()` or `poll_asm_issues()`) to filter issues by criteria like severity or `asset_type`. For polling, adjust `polls` and `interval` in `ingest_asm_issues_with_polling.py` to control polling frequency. Refer to inline comments and the "**Input Parameters**" section for guidance on formats.

### 5.  Review Output

The scripts generate formatted JSON output for ASM issues per request or poll. Example outputs are available in the `/asm` directory. For instance, the output of the `ingest_asm_issues.py` script can be found in the `ingest_asm_issues_output.md` file.Similar output files are provided for other scripts in the same directory, offering example results and detailed explanations of the JSON structure.


## Additional Notes
  - **Query Customization**: Adjust the `query_string` in either script to filter issues by criteria like `severity`, `asset_type`, or `last_seen_after`. Refer to the GTI API documentation for valid query syntax.

  - **API Quota Management**: Both scripts include retry logic for HTTP 429 (rate limit) and 5xx errors. Monitor API usage to stay within your quota, especially during frequent polling.

  - **Error Handling**: The scripts handle network failures, invalid responses, and parsing errors, providing clear feedback and retry suggestions. Check console output for error details.

  - **Output Storage**: By default, outputs are printed to the console. Modify the scripts to save issue data to a file (e.g., JSON or CSV) for integration with SIEM or asset management systems.

  - **Script Documentation**: Both scripts contain detailed comments explaining their functionality, parameters, and error handling.

  - **GTI API Documentation**: For endpoint details and query syntax, refer to the official [GTI Documentation](https://gtidocs.virustotal.com/reference/get_search-issues-search-string).

  - **Troubleshooting**: Create a `docs/troubleshooting.md` file for common issues like API errors, rate limits, or invalid queries, or refer to console output for error details.

  - **Integration Tips**: Use the scripts’ output to create incidents in your platform, correlate ASM assets with internal inventories, and send status updates back to the GTI API using appropriate endpoints (e.g., `/asm/issues/{id}/status`).

