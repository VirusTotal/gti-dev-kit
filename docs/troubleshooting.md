# Troubleshooting Google Threat Intelligence (GTI) API Example Scripts

This document provides guidance for troubleshooting common issues encountered when using the Google Threat Intelligence (GTI) API example scripts in the `examples` folder. It covers error handling, common error codes, and steps to resolve issues effectively, referencing the scripts' functionality and structure.

---

## 1. Overview

The provided scripts interact with the GTI API to perform tasks such as threat intelligence enrichment, data ingestion, and file/URL scanning. Each script includes robust error handling via the `make_api_request` function, which returns a dictionary with keys: `success`, `data`, `error`, `status_code`, and `should_retry`. This guide explains how to diagnose and resolve issues across these scripts, with specific considerations for their unique functionalities (e.g., file uploads, URL encoding, polling).

---

## 2. Common Error Scenarios and Solutions

### 2.1 HTTP Status Code Errors

The `make_api_request` function handles various HTTP status codes consistently across all scripts. Below are common errors, their causes, and troubleshooting steps.

| **HTTP Status Code** | **Error Message** | **Description** | **Troubleshooting Steps** |
|----------------------|-------------------|-----------------|---------------------------|
| **400 (Bad Request)** | Varies (e.g., "Bad request - invalid parameters", "Bad request - invalid URL or parameters", "Bad request - invalid IP address or parameters") | Malformed query parameters, URLs, or IP addresses. | - **For `enrich_domain.py`**: Ensure the domain (e.g., `www.google.com`) is valid and properly formatted.<br>- **For `enrich_url.py`**: Verify the URL is correctly formatted (e.g., includes `https://`). Check for proper base64 encoding in `get_url_report`.<br>- **For `enrich_ip.py`**: Confirm the IP address (e.g., `8.8.8.8`) is valid (IPv4/IPv6).<br>- **For `ingest_asm_issues.py`**: Validate the `query_string` syntax (e.g., `severity:5 last_seen_after:2025-08-01T00:00:00Z`).<br>- **For `ingest_dtm_alerts.py`**: Check `params` (e.g., `since`, `size`) against [DTM Alerts](https://gtidocs.virustotal.com/reference/get-alerts).<br>- **For `ingest_threat_list.py`**: Ensure `list_name` is valid (e.g., `ransomware`, `phishing`).<br>- Refer to [GTI Documentation](https://gtidocs.virustotal.com/reference/api-overview) for endpoint-specific parameters. |
| **401 (Unauthorized)** | "Unauthorized - invalid API key" | Incorrect or missing API key. | - Verify `GTI_API_KEY` is set correctly in each script.<br>- Copy correct api key from GoogleThreatIntelligence dashboard.<br>- Ensure the key has permissions for the relevant endpoints (e.g., ASM, DTM, private scanning).<br>- Test with `curl`:<br>  ```bash<br>  curl -H "x-apikey: YOUR_API_KEY" -H "x-tool: YOUR_PRODUCT_NAME" "https://www.virustotal.com/api/v3/domains/example.com"<br>  ``` |
| **403 (Forbidden)** | "Forbidden - insufficient permissions" | API key lacks permissions for the endpoint. | - Check the API key’s scope in the GoogleThreatIntelligence dashboard.<br>- Confirm access to premium features (e.g., ASM in `ingest_asm_issues.py`, DTM in `ingest_dtm_alerts.py`, private scanning in `scan_file.py`/`scan_url.py`).<br>- Contact GoogleThreatIntelligence support for clarification. |
| **404 (Not Found)** | Varies (e.g., "Resource not found", "URL not found in the database", "IP address not found in the database", "Endpoint not found", "Threat list not found") | Endpoint or resource does not exist. | - **For `enrich_domain.py`/`enrich_file.py`/`enrich_ip.py`/`enrich_url.py`**: Ensure the domain, file hash, IP, or URL exists in the GTI database. Test with known malicious IOCs.<br>- **For `ingest_asm_issues.py`**: Verify the endpoint `asm/search/issues/{query_string}`.<br>- **For `ingest_threat_list.py`**: Confirm the `list_name` is valid (e.g., `ransomware`).<br>- Check [GTI Documentation](https://gtidocs.virustotal.com/reference/api-overview) for correct endpoint paths. |
| **5xx (Server Errors)** | "Server error (HTTP {status_code})" | Temporary server-side issue. | - Check `should_retry` flag (set to `True` for 5xx errors).<br>- Retry after a delay (e.g., 5-10 seconds).<br>- Contact GoogleThreatIntelligence support if persistent. |

### 2.2 Network and Request Errors

| **Error Type** | **Error Message** | **Description** | **Troubleshooting Steps** |
|----------------|-------------------|-----------------|---------------------------|
| **Timeout** | "Request timed out" | Request exceeds 15-second timeout (60 seconds for `scan_file.py`/`scan_url.py`). | - Check network connectivity and latency.<br>- Increase `timeout` in `make_api_request` if needed.<br>- Retry the request (scripts set `should_retry=True`).<br>- For `scan_file.py`, reduce file size or use a special upload URL for large files.<br>- For `ingest_ioc_stream.py`, reduce `polls` or `interval` to manage load. |
| **Connection Error** | "Connection error - check your network" | Network issues prevent API access. | - Verify internet connectivity.<br>- Check firewall/proxy settings for `https://www.virustotal.com`.<br>- Retry the request (scripts set `should_retry=True`).<br>- Test with `ping` or `curl` to confirm connectivity. |
| **Request Exception** | "Request failed: {error}" | General request failure (e.g., SSL issues). | - Update `requests` library: `pip install --upgrade requests`.<br>- Check for SSL/TLS issues (e.g., outdated certificates, system time sync).<br>- Log raw response for debugging: `print(response.text)`. |
| **JSON Parsing Error** | "Failed to parse JSON response: {error}" | Invalid JSON response from API. | - Log raw `response.text` to inspect server output.<br>- Check for server maintenance or errors.<br>- Contact GoogleThreatIntelligence support if persistent. |
| **Unexpected Error** | "Unexpected error: {error}" | Unhandled exceptions in script logic. | - Log full stack trace for debugging.<br>- Review script for unhandled edge cases.<br>- Update script to handle specific exceptions if recurring. |

### 2.3 Script-Specific Issues

#### 2.3.1 Enrichment Scripts (`enrich_domain.py`, `enrich_file.py`, `enrich_ip.py`, `enrich_url.py`)

| **Issue** | **Description** | **Troubleshooting Steps** |
|-----------|---------------|---------------------------|
| **No Data Returned** | Empty or missing `data` in response. | - Verify the IOC (domain, file hash, IP, URL) exists in GTI database.<br>- Test with known malicious IOCs (e.g., known malware hash for `enrich_file.py`).<br>- For `enrich_url.py`, ensure URL is properly encoded in `get_url_report` (base64 encoding). |
| **Missing Relationships** | No relationships in output (e.g., `collections`, `malware_families`). | - Check `RELATIONSHIPS` and `RELATIONSHIP_ATTRIBUTES` in script configuration.<br>- Confirm API key has access to relationship data (premium feature).<br>- Test with a known malicious IOC to ensure relationships exist. |
| **Invalid File Hash (`enrich_file.py`)** | File hash format is incorrect. | - Use a valid SHA-256, SHA-1 and MD-5 hash (e.g., `0078c8132fb99b4bccbb2e2429885a857d6a89534f74e23e6a12821abd2c3db2`).|
| **No MITRE Data (`enrich_file.py`)** | `get_mitre_data` returns no data. | - Confirm file hash has associated MITRE ATT&CK data.<br>- Check API key permissions for `/files/{file_hash}/behaviour_mitre_trees`.<br>- Test with a known malicious file hash. |
| **URL Encoding Error (`enrich_url.py`)** | `Failed to encode URL: {error}` in `get_url_report`. | - Ensure URL is valid and properly formatted (e.g., `https://www.youtube.com/`).<br>- Debug base64 encoding logic in `get_url_report`.<br>- Try a simple URL to rule out encoding issues. |

#### 2.3.2 Ingestion Scripts (`ingest_asm_issues.py`, `ingest_dtm_alerts.py`, `ingest_ioc_stream.py`, `ingest_threat_list.py`)

| **Issue** | **Description** | **Troubleshooting Steps** |
|-----------|---------------|---------------------------|
| **No ASM Issues (`ingest_asm_issues.py`)** | `No ASM issues found matching the query.` | - Validate `query_string` syntax (e.g., `severity:5 last_seen_after:2025-08-01T00:00:00Z`).<br>- Ensure `last_seen_after` date is recent and ISO 8601 formatted.<br>- Test with broader query (e.g., remove `severity:5`).<br>- Confirm ASM feature access for your account. |
| **No DTM Alerts (`ingest_dtm_alerts.py`)** | `No DTM alerts found matching the criteria.` | - Check `params` (e.g., `since`, `monitor_id`, `severity`) in `main`.<br>- Ensure `since` date is recent and valid.<br>- Verify monitor setup in GoogleThreatIntelligence dashboard.<br>- Test with minimal `params` (e.g., `{"size": 100, "order": "desc"}`). |
| **No IOCs (`ingest_ioc_stream.py`)** | `No new IOCs received in this poll.` | - Confirm subscription to IOC stream in GoogleThreatIntelligence dashboard.<br>- Check `cursor` handling in `process_ioc_stream`.<br>- Reduce `interval` or increase `polls` to capture more data.<br>- Test with a known active IOC stream. |
| **No Threat List IOCs (`ingest_threat_list.py`)** | `No IOCs found in the '{list_name}' threat list.` | - Verify `list_name` is valid (e.g., `ransomware`, `phishing`).<br>- Check API key permissions for threat lists.<br>- Test with another category (e.g., `malware`). |

#### 2.3.3 Scanning Scripts (`scan_file.py`, `scan_url.py`)

| **Issue** | **Description** | **Troubleshooting Steps** |
|-----------|---------------|---------------------------|
| **File Not Found (`scan_file.py`)** | `File not found: {file_path}` | - Ensure `file_path` exists and is accessible (e.g., `dummy_private_file.txt`).<br>- Check file permissions and path accuracy.<br>- Create a test file if needed. |
| **Empty File (`scan_file.py`)** | `Error: File is empty` | - Ensure file has content (non-zero size).<br>- Test with a non-empty dummy file. |
| **Large File Upload Failure (`scan_file.py`)** | `Error getting upload URL` or `Error uploading file` | - Verify file size against `MAX_DIRECT_UPLOAD_SIZE` (32MB).<br>- Check `get_upload_url` response for valid URL.<br>- Retry with a smaller file to rule out size issues. |
| **Analysis Timeout (`scan_file.py`, `scan_url.py`)** | `Max polling attempts reached` | - Increase `MAX_POLLING_ATTEMPTS` or `POLLING_INTERVAL`.<br>- Check `poll_analysis_status` for status (e.g., `error`, `unsupported file type`).<br>- Test with a smaller file or simpler URL.<br>- Monitor server status for delays. |
| **Invalid URL (`scan_url.py`)** | `Bad request - invalid URL or parameters` | - Ensure URL is valid (e.g., `https://www.youtube.com/`).<br>- Check `submit_url_for_scanning` payload formatting.<br>- Test with a simple URL. |
| **No Analysis ID/URL ID** | `Error: No analysis ID received` or `Error: No URL ID received` | - Log raw response from `submit_url_for_scanning` or `poll_analysis_status`.<br>- Check API key permissions for private scanning endpoints.<br>- Verify endpoint paths in [GTI Documentation](https://gtidocs.virustotal.com/reference/api-overview). |

