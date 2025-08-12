# Google Threat Intelligence (GTI) Digital Threat Monitoring (DTM) Alerts Script

This repository contains Python scripts designed to interface with the Google Threat Intelligence (GTI) API to fetch Digital Threat Monitoring (DTM) alerts. DTM continuously monitors the deep and dark web for mentions of specific topics or entities (e.g., brand names, credentials) defined in organizational Monitors, generating alerts for potential threats like phishing campaigns, brand impersonation, or data leaks. These scripts enable security teams to proactively identify and mitigate external threats by retrieving and processing DTM alerts efficiently.

## Overview

The `ingest_dtm_alerts.py` and `ingest_dtm_alerts_with_polling.py` scripts streamline the retrieval of DTM alerts from the GTI API, providing structured JSON output for easy analysis. They support configurable query parameters (e.g., time range, severity, alert type) and robust error handling for reliable operation. The polling script adds pagination and periodic querying to keep alert data current, making it ideal for continuous monitoring. These scripts facilitate integration with security platforms to create incidents, track alert status, and synchronize updates with the GTI platform.

## DTM Support
  - **Objective**: Integrate DTM alerts from GTI to proactively identify and mitigate external threats like phishing campaigns, brand impersonation, and data leaks.

  - **Key Implementation Points**:
      - Automatically create corresponding incidents, cases, or alerts in the host platform based on ingested DTM data.
      - Provide mechanisms to track the status of a DTM alert, from discovery to takedown.
      - Ensure the integration can handle large volumes of DTM data efficiently without causing performance issues or blocking the application/platform instance.
      - Send DTM alert updates, such as status changes, back to the GTI platform to keep data in sync.

  - **Relevant API Calls**:
      - `/dtm/alerts`: Fetches DTM alerts based on query parameters like time range, severity, and alert type.

  - **User Experience (UX) Best Practice**:
      - Automatically prioritize DTM alerts based on severity to streamline analyst workflows and focus on high-risk threats.

  - **Configuration Tip**:
      - Allow users to create filtering rules to specify which types of DTM alerts (e.g., phishing, malware, brand abuse) should be automatically ingested and escalated. Configure polling intervals and alert limits to balance API quota and data freshness.

  - [**Best Practices Guide**](https://docs.google.com/document/d/1foYWa5FnlwtYBIo63YIZU5AOInI7UsNdrn9g0ty25Ag/edit?resourcekey=0-SIeMz9ALACxg0qGd75Jm4g&tab=t.0#heading=h.chtbelhjcoah)

## Key Features
  - **DTM Alert Retrieval**: Queries the GTI DTM alerts endpoint with configurable parameters (e.g., time range, severity, alert type, monitor_id, status, alert_type etc.) to fetch relevant alerts.

  - **Threat Detection**: Monitors for brand mentions, credential leaks, or sensitive information on the deep and dark web, critical for security operations.

  - **Structured Output**: Extracts and presents alert data in formatted JSON for clear, actionable insights.

  - **Error Handling**: Implements robust handling of HTTP errors, rate limits, and network issues, with retry logic for transient failures.

  - **Pagination Handling**: Supports automatic parsing of pagination tokens to navigate through large sets of alerts (in `ingest_dtm_alerts_with_polling.py`).

  - **Polling Mechanism**: Enables periodic polling with configurable intervals to keep alert data current (in `ingest_dtm_alerts_with_polling.py`).

  - **Scalable Integration**: Handles high-volume DTM data efficiently, supporting integration with incident management systems and status synchronization.

## Use Case: Mapping DTM Alerts to SOAR Incidents
- Ingest DTM alerts (e.g., exposed credentials, impersonation attempts) into SOAR.
- Enables SOC analysts to:
  - Investigate threat sources and severity.
  - Validate exposures and take action to mitigate risks.

## Scripts Overview
The repository includes the following scripts, tailored to fetch and process DTM alerts from the GTI API for threat monitoring and analysis.

#### `ingest_dtm_alerts.py`
  - **Purpose**: Fetches DTM alerts from the GTI API with configurable parameters, displaying up to three alerts in a formatted JSON output.

  - **Key Features**:
      - **DTM Alert Retrieval**: Queries the `/dtm/alerts` endpoint with filters like date, score, severity, and alert type.
      - **Threat Detection**: Identifies mentions of monitored entities (e.g., brand names, credentials) on the deep and dark web.
      - **Structured Output**: Presents alert data in a clear, formatted JSON structure.
      - **Error Handling**: Manages API request failures (e.g., network issues, HTTP errors) with retry suggestions.

  - **API Endpoints Used**:
      - `/dtm/alerts`: Fetches DTM alerts based on query parameters.

  - **Use Case**: One-time retrieval of DTM alerts for initial threat analysis or manual review.

#### `ingest_dtm_alerts_with_polling.py`
  - **Purpose**: Fetches DTM alerts with pagination and periodic polling, displaying up to three alerts per poll in a formatted JSON output.

  - **Key Features**:
      - **DTM Alert Retrieval**: Queries the `/dtm/alerts` endpoint with configurable parameters.
      - **Pagination Handling**: Parses pagination tokens from response headers to handle large datasets.
      - **Error Handling**: Manages HTTP errors, rate limits, and network issues with retry logic.
      - **Polling Mechanism**: Polls the API at configurable intervals for continuous monitoring.
      - **Structured Output**: Presents alert data in formatted JSON for quick analysis.

  - **API Endpoints Used**:
      - `/dtm/alerts`: Fetches DTM alerts with pagination support.

  - **Use Case**: Continuous monitoring of DTM alerts for real-time threat detection and integration with security platforms.

## Input Parameters
  - **monitor_id**
      - **Description**: Only return alerts for the given monitor IDs
      - **Example**: ["amazon123dft", "sfdsfds123"]

  - **since**
      - **Description**: Time from when alerts should be retrieved (must be within the last 5 days)
      - **Example**: "2025-05-10T00:00:00+00:00"

  - **status**
      - **Description**: Filter alerts by their status. This parameter can be specified multiple times. Possible values are new, read, escalated, in_progress, closed, no_action_required, duplicate, not_relevant, and tracked_external
      - **Example**: ["new", "read"]

  - **alert_type**
      - **Description**: Filter alerts by alert type. This parameter can be specified multiple times. Possible values are Compromised Credentials, Domain Discovery, Forum Post, Message, Paste, Shop Listing, Tweet, and Web Content
      - **Example**: ["Paste", "Message"]

  - **tags**
      - **Description**: Filter alerts by tag(s). This parameter can be used more than once to filter on multiple tags
      - **Example**: ["amazon"]

  - **match_value**
      - **Description**: If specified, then only alerts that have the given match value are returned. This parameter can be repeated multiple times
      - **Example**: ["amazon"]

  - **severity**
      - **Description**: Return alerts that have the given severity. This parameter can be repeated multiple times. Possible values are high, medium and low
      - **Example**: ["low", "medium"]

  - **mscore_gte**
      - **Description**: Filter alerts with mscores greater than or equal to the given value
      - **Example**: 50

  - **search**
      - **Description**: Search alert and triggering doc contents based on a simple Lucene query string including 1 or more text values separated by AND or OR
      - **Example**: "severity:50"

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

Navigate to the `dtm` directory and execute the desired script using Python from the command line.

  - For one-time alert retrieval:
    ```bash
    python ingest_dtm_alerts.py
    ```

  - For continuous polling:
    ```bash
    python ingest_dtm_alerts_with_polling.py
    ```

### 4.  Customize Inputs

Modify the query parameters in the scripts (e.g., `params` in `main()` or `poll_dtm_alerts()`) to filter alerts by criteria like `since`, `severity`, or `alert_type`. For polling, adjust `polls` and `interval` in `ingest_dtm_alerts_with_polling.py` to control polling frequency. Refer to inline comments for guidance on parameters and formats.

### 5.  Review Output
The scripts generate formatted JSON output for up to three DTM alerts per request or poll. Example outputs are available in the `/dtm` directory. For instance, the output of the `ingest_dtm_alerts.py` script can be found in the `ingest_dtm_alerts_output.md` file.Similar output files are provided for other scripts in the same directory, offering example results and detailed explanations of the JSON structure.


## Additional Notes
  - **Query Customization**: Adjust the `params` dictionary in either script to filter alerts by criteria like `severity`, `alert_type`, or `monitor_id`. Refer to the GTI API documentation for valid filter values.

  - **API Quota Management**: Both scripts include retry logic for HTTP 429 (rate limit) and 5xx errors. Monitor API usage to stay within your quota, especially during frequent polling.

  - **Error Handling**: The scripts handle network failures, invalid responses, and parsing errors, providing clear feedback and retry suggestions. Check console output for error details.

  - **Script Documentation**: Both scripts contain detailed comments explaining their functionality, parameters, and error handling.

  - **Output Storage**: By default, outputs are printed to the console. Modify the scripts to save alert data to a file (e.g., JSON or CSV) for integration with SIEM or incident management systems.

  - **GTI API Documentation**: For endpoint details and query syntax, refer to the official [GTI Documentation](https://gtidocs.virustotal.com/reference/get-alerts).

  - **Troubleshooting**: Create a `docs/troubleshooting.md` file for common issues like API errors, rate limits, or invalid filters, or refer to console output for error details.

  - **Integration Tips**: Use the scripts’ output to create incidents in your platform, track alert status (e.g., new, resolved), and send status updates back to the GTI API using appropriate endpoints (e.g., `/dtm/alerts/{id}`).
