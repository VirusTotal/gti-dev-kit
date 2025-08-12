# Google Threat Intelligence (GTI) File and URL Scanning Scripts

This repository contains a collection of Python scripts designed to interface with the Google Threat Intelligence (GTI) API to scan files and URLs for malicious content. These scripts support both private and public scanning workflows, enabling security analysts, incident responders, and developers to assess the threat level of files and URLs in secure or public environments. The scripts handle submission, polling, and report retrieval, providing detailed verdicts and GTI assessments.

## Overview

The scripts streamline file and URL scanning workflows by submitting files or URLs to the GTI API, polling for analysis completion, and presenting detailed scan reports. They are designed to support security operations by providing actionable insights into potential threats, including verdicts, detection statistics, and GTI assessments. Each script includes robust error handling, support for large file uploads, and structured output for easy consumption.

## Private Scanning

  - **Objective**: Enable users to securely submit suspicious files or URLs for private analysis without sharing them with the public GTI community.

  - **Key Implementation Points**:
      - Use the appropriate GTI API endpoint designated for private submissions to ensure submitted data remains confidential.
      - Implement a mechanism to clearly display the scanning report, including sandbox behavior, verdicts, and extracted IOCs.
      - Handle large file uploads gracefully, providing feedback on the upload progress and managing potential network timeouts.

  - **Relevant API Calls**:
      - `/private/files/upload`: Upload a file for private scanning (small files up to 32MB).
      - `/private/files/upload_url`: Retrieve a special upload URL for large files (>32MB).
      - `/private/urls`: Submit a URL for private scanning.
      - `/analyses/{analysis_id}`: Poll the analysis status for files or URLs.
      - `/private/files/{file_hash}`: Retrieve the final report for a privately scanned file.
      - `/private/urls/{url_id}`: Retrieve the final report for a privately scanned URL.

  - **User Experience (UX) Best Practice**:
      - Provide a clear "Submit for Private Analysis" option and display a status indicator showing that the scan is in progress, complete, or has failed.

  - **Configuration Tip**:
      - The integration should require users to explicitly acknowledge that the submission is private, ensuring they understand the data handling process.

  - [**Best Practices Guide**](https://docs.google.com/document/d/1foYWa5FnlwtYBIo63YIZU5AOInI7UsNdrn9g0ty25Ag/edit?resourcekey=0-SIeMz9ALACxg0qGd75Jm4g&tab=t.0#heading=h.yd8po5neuk0z)

## Public Scanning

  - **Objective**: Enable users to submit files or URLs for scanning and share the resulting analysis with the broader Google Threat Intelligence (GTI) community, benefiting from crowd-sourced detection insights.

  - **Key Implementation Points**:
      - Use GTI's public API endpoints to submit files or URLs for scanning where results are visible to other GTI users.
      - Leverage community-driven detection engines and metadata to enrich investigations.
      - Present verdicts, threat scores, and GTI assessments in a clear, human-readable format.
      - Poll for scan completion and retrieve full analysis reports after processing.

  - **Relevant API Calls**:
      - `/files`: Upload a small file (up to 32MB) for public scanning.
      - `/files/upload_url`: Obtain a special upload URL to submit large files (>32MB).
      - `/urls`: Submit a URL for public scanning.
      - `/analyses/{analysis_id}`: Poll the scan status using the returned analysis ID.
      - `/files/{file_hash}`: Retrieve the final scan report for a submitted file.
      - `/urls/{url_id}`: Retrieve the final scan report for a submitted URL.

  - **User Experience (UX) Best Practice**:
      - Clearly label public scan actions and show when the scan result is ready.
      - Display confidence scores, contributing factors, and sandbox verdicts in the UI or console.

  - **Configuration Tip**:
      - Ensure that users are aware that public scans will share scan results with the GTI community.
      - Use public scanning only for non-sensitive or already public data. Avoid submitting confidential files or internal URLs.
      - Clearly separate private and public scanning configurations in the UI or integration logic to prevent accidental data exposure.

## Key Features

  - **Support for File and URL Scanning**: Scan local files (up to 32MB directly, larger files via special upload URLs) and URLs for malicious content.
  - **Private and Public Scanning**: Offers private scanning for confidential submissions and public scanning for community-shared analysis.
  - **Manual Scanning**: Allows analysts to trigger scans directly from a security platform's UI with a one-click or right-click context menu action, displaying critical results like verdicts and GTI assessments.
  - **Dynamic File Sizing**: Intelligently handles small files (up to 32MB) with direct uploads and larger files by obtaining special upload URLs.
  - **Analysis Polling**: Continuously polls the GTI API to monitor analysis status, ensuring reports are retrieved only after scan completion.
  - **Structured Output**: Presents verdicts (malicious/clean), detection counts, GTI assessments, and full JSON reports in a human-readable format.
  - **Robust Error Handling**: Gracefully handles file not found errors, network issues, API errors, invalid responses, and retry logic for transient failures.
  - **GTI GUI Deep Links**: Provides direct links to the GTI web interface for each scanned file or URL, enabling seamless transitions to manual investigation.

## SOAR Use Case: File and URL Scanning
  - **Private Scanning**:
      - Submit sensitive files/URLs (e.g., from phishing alerts) for analysis.
      - Trigger actions based on results (e.g., block, isolate, escalate).
  - **Public Scanning**:
      - Analyze open-source IOCs with community-based detections.
      - Enrich alerts and check prior scan history to optimize analysis.

## Scripts Overview

The repository includes the following scripts, organized into "Private Scanning" and "Public Scanning" directories. Each script is tailored to a specific scanning goal, with details on its key features and GTI API endpoints used.

### Private Scanning
Scripts in this category submit files or URLs to GTI's private analysis endpoints, ensuring confidentiality of submitted data.

#### `scan_file.py`

  - **Purpose**: Submits a local file to the GTI API for private analysis, polling for completion and retrieving the final threat report.

  - **Key Features**:
      - **File Upload**: The script handles the upload of a local file to the GTI API for analysis.
      - **Dynamic File Sizing**: It intelligently manages both small files (up to 32MB) with a direct upload and larger files (over 32MB) by first obtaining a special upload URL, ensuring a robust and scalable solution.
      - **Analysis Polling**: After a file is uploaded, the script continuously polls the API to monitor the analysis status. This ensures that the final report is not returned until the scanning process is fully completed.
      - **Final Report**: Upon completion, the script fetches and prints the final analysis report, including the threat verdict (malicious or clean) and the GTI's assessment.
      - **Robust Error Handling**: The script includes comprehensive error handling to gracefully manage issues such as file not found errors, failed API requests, and invalid responses.

  - **API Endpoints Used**:
      - `/private/files/upload`: Uploads small files (up to 32MB) directly for private scanning.
      - `/private/files/upload_url`: Retrieves a special upload URL for large files (>32MB).
      - `/analyses/{analysis_id}`: Polls the analysis status for the uploaded file.
      - `/private/files/{file_hash}`: Fetches the final threat intelligence report for the scanned file.

  - **Use Case**: Securely analyzing sensitive files without sharing them with the GTI community.

#### `scan_url.py`

  - **Purpose**: Submits a URL to the GTI API for private analysis, polling for completion and retrieving the final threat report.

  - **Key Features**:
      - URL Submission: Submits a specified URL to the private analysis endpoint.
      - Continuous Polling: Polls the API for the analysis status until the scan is complete.
      - Report Retrieval: Fetches and displays the final scan report, including the verdict and GTI's assessment of the URL.
      - Error Handling: Includes robust error handling for network issues, invalid URLs, and API response errors.

  - **API Endpoints Used**:
      - `/private/urls`: Submits the URL for private scanning.
      - `/analyses/{analysis_id}`: Polls the analysis status for the submitted URL.
      - `/private/urls/{url_id}`: Fetches the final threat intelligence report for the scanned URL.

  - **Use Case**: Evaluating the safety of URLs in a confidential manner, such as for internal phishing investigations.

### Public Scanning
Scripts in this category submit files or URLs to GTI's public analysis endpoints, where results are shared with the GTI community.

#### `scan_file.py`

  - **Purpose**: Submits a local file to the GTI API for public analysis, polling for completion and retrieving the final threat report.

  - **Key Features**:
      - **File Upload**: The script handles the upload of a local file to the GTI API for analysis.
      - **Dynamic File Sizing**: It intelligently manages both small files (up to 32MB) with a direct upload and larger files (over 32MB) by first obtaining a special upload URL, ensuring a robust and scalable solution.
      - **Analysis Polling**: After a file is uploaded, the script continuously polls the API to monitor the analysis status, ensuring the final report is not returned until the scanning process is fully completed.
      - **Final Report**: Upon completion, the script fetches and prints the final analysis report, including the threat verdict (malicious or clean) and the GTI's assessment.
      - **Robust Error Handling**: The script includes comprehensive error handling to gracefully manage issues such as file not found errors, failed API requests, and invalid responses.

  - **API Endpoints Used**:
      - `/files`: Uploads small files (up to 32MB) directly for public scanning.
      - `/files/upload_url`: Retrieves a special upload URL for large files (>32MB).
      - `/analyses/{analysis_id}`: Polls the analysis status for the uploaded file.
      - `/files/{file_hash}`: Fetches the final threat intelligence report for the scanned file.

  - **Use Case**: Analyzing files in a public context to leverage community-driven threat intelligence.

#### `scan_url.py`

  - **Purpose**: Submits a URL to the GTI API for public analysis, polling for completion and retrieving the final threat report.

  - **Key Features**:
      - **URL Submission**: Submits a specified URL to the public analysis endpoint.
      - **Continuous Polling**: It includes a robust polling loop that continuously checks the analysis status until the scan is complete.
      - **Report Retrieval**: Fetches and displays the final scan report, including the verdict (e.g., malicious or clean) and the GTI's assessment of the URL.
      - **Error Handling**: The script includes comprehensive error handling to gracefully manage issues such as failed API requests and invalid responses.

  - **API Endpoints Used**:
      - `/urls`: Submits the URL for public scanning.
      - `/analyses/{analysis_id}`: Polls the analysis status for the submitted URL.
      - `/urls/{url_id}`: Fetches the final threat intelligence report for the scanned URL.

  - **Use Case**: Assessing URLs for malicious content in a public, community-shared environment.

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

### 3. Run the Scripts
Navigate to the `file_and_url_scanning` directory and execute the desired script using Python from the command line.

  - For Scan Private File:
    ```bash
    python private_scanning/scan_file.py
    ```

  - For Scan Public File:
    ```bash
    python public_scanning/scan_file.py
    ```

### 4. Customize Inputs

Modify the default inputs in each script (e.g., domain, file hash, URL) as needed. Refer to inline comments for guidance on required parameters and formats.

### 5. Review Output

Each script formats the output in a human-readable JSON structure, You can view the results directly in the console, or modify the script to save the output to a file if needed.

Additionally, example outputs are provided in the `/private_scannig` directory. For instance, the output of the `scan_file.py` script can be found in the `scan_file_output.md` file. Similar output files are provided for other scripts in the same directory, offering example results and detailed explanations of the JSON structure.


## Additional Notes

   - **Script Documentation**: Each script contains detailed comments explaining its functionality, parameters, and error handling.

   - **GTI API Documentation**: For endpoint details and query syntax, refer to the official GTI Documentation.
      - [Public File Scan Documentation](https://gtidocs.virustotal.com/reference/files-scan)
      - [Public File Analysis Documentation](https://gtidocs.virustotal.com/reference/analysis)
      - [Public File Report Documentation](https://gtidocs.virustotal.com/reference/file-info)
      - [Private File Scan Documentation](https://gtidocs.virustotal.com/reference/upload-file-private-scanning)
      - [Private File Analysis Documentation](https://gtidocs.virustotal.com/reference/private-analysis)
      - [Private File Report Documentation](https://gtidocs.virustotal.com/reference/private-files-info)
      - [Public URL Scan Documentation](https://gtidocs.virustotal.com/reference/scan-url)
      - [Public URL Analysis Documentation](https://gtidocs.virustotal.com/reference/analysis)
      - [Public URL Report Documentation](https://gtidocs.virustotal.com/reference/url-info)
      - [Private URL Scan Documentation](https://gtidocs.virustotal.com/reference/private-scan-url)
      - [Private URL Analysis Documentation](https://gtidocs.virustotal.com/reference/private-analysis)
      - [Private URL Report Documentation](https://gtidocs.virustotal.com/reference/get-a-private-url-analysis-report)


   - **API Quota Management**: Both scripts include retry logic for HTTP 429 (rate limit) and 5xx errors. Monitor API usage to stay within your quota, especially during frequent polling.

   - **Error Handling**: The scripts handle network failures, invalid responses, and parsing errors, providing clear feedback and retry suggestions. Check console output for error details.

   - **Troubleshooting**: Refer to `troubleshooting.md` in the `/docs` folder for help with common issues like API errors, rate limits, or invalid inputs.

