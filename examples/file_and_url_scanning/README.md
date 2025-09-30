# **Google Threat Intelligence (GTI) File and URL Scanning Scripts**

This repository contains a collection of Python scripts designed to interface with the Google Threat Intelligence (GTI) API to scan files and URLs for malicious content. These scripts support **both private and public scanning** workflows, enabling security analysts, incident responders, and developers to review the threat level of files and URLs in a secure, private sandbox, or by uploading it to the public GTI corpus to crowdsource the assessment. The scripts handle submission, polling, and report retrieval, providing detailed verdicts and GTI assessments.

## **Overview**

The scripts streamline file and URL scanning workflows by submitting files or URLs to the GTI API, polling for analysis completion, and presenting detailed scan reports. They are designed to support security operations by providing actionable insights into potential threats, including verdicts, detection statistics, and GTI assessments. Each script includes robust error handling, support for large file uploads, and structured output for easy consumption.

## **Private Scanning**

- **Objective**: Enable users to securely submit suspicious files or URLs for private analysis **without sharing them with the public GTI community**.  
    
- **Key Implementation Points**:  
    
  - Use the appropriate GTI API endpoint designated for private submissions to ensure submitted data remains confidential.  
  - Implement a mechanism to clearly display the scanning report, including sandbox behavior, verdicts, and extracted IOCs.  
  - Handle large file uploads gracefully, providing feedback on the upload progress and managing potential network timeouts.


- **Relevant API Calls**:  
    
  - `/private/files/upload`: Upload a file for private scanning (small files up to 32MB).  
  - `/private/files/upload_url`: Retrieve a special upload URL for large files (\>32MB).  
  - `/private/urls`: Submit a URL for private scanning.  
  - `/analyses/{analysis_id}`: Poll the analysis status for files or URLs.  
  - `/private/files/{file_hash}`: Retrieve the final report for a privately scanned file.  
  - `/private/urls/{url_id}`: Retrieve the final report for a privately scanned URL.


- **User Experience (UX) Best Practice**:  
    
  - Provide a clear "Submit for Private Analysis" option and display a status indicator showing that the scan is in progress, complete, or has failed.


- **Configuration Tip**:  
    
  - The integration should require users to explicitly acknowledge that the submission is private, ensuring they understand the data handling process.

## **Public Scanning**

- **Objective**: Enable users to submit files or URLs for scanning **and share the resulting analysis with the broader Google Threat Intelligence (GTI) community**, benefiting from crowd-sourced detection insights.  
    
- **Key Implementation Points**:  
    
  - Use GTI's public API endpoints to submit files or URLs for scanning where results are visible to other GTI users.  
  - Leverage community-driven detection engines and metadata to enrich investigations.  
  - Present verdicts, threat scores, and GTI assessments in a clear, human-readable format.  
  - Poll for scan completion and retrieve full analysis reports after processing.


- **Relevant API Calls**:  
    
  - `/files`: Upload a small file (up to 32MB) for public scanning.  
  - `/files/upload_url`: Obtain a special upload URL to submit large files (\>32MB).  
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

## **Scripts Overview**

The repository includes the following scripts, organized into "Private Scanning" and "Public Scanning" directories. Each script is tailored to a specific scanning goal, with details on its key features and GTI API endpoints used.

### **Private Scanning**

Scripts in this category submit files or URLs to GTI's private analysis endpoints, ensuring confidentiality of submitted data.

#### **`scan_file.py`**

- **Purpose**: Submits a local file to the GTI API for private analysis, polling for completion and retrieving the final threat report.  
    
- **Key Features**:  
    
  - **File Upload**: The script handles the upload of a local file to the GTI API for analysis.  
  - **Dynamic File Sizing**: It intelligently manages both small files (up to 32MB) with a direct upload and larger files (over 32MB) by first obtaining a special upload URL, ensuring a robust and scalable solution.  
  - **Analysis Polling**: After a file is uploaded, the script continuously polls the API to monitor the analysis status. This ensures that the final report is not returned until the scanning process is fully completed.  
  - **Final Report**: Upon completion, the script fetches and prints the final analysis report, including the threat verdict (malicious or clean) and the GTI's assessment.  
  - **Robust Error Handling**: The script includes comprehensive error handling to gracefully manage issues such as file not found errors, failed API requests, and invalid responses.


- **API Endpoints Used**:  
    
  - `/private/files/upload`: Uploads small files (up to 32MB) directly for private scanning.  
  - `/private/files/upload_url`: Retrieves a special upload URL for large files (\>32MB).  
  - `/analyses/{analysis_id}`: Polls the analysis status for the uploaded file.  
  - `/private/files/{file_hash}`: Fetches the final threat intelligence report for the scanned file.


- **Use Case**: Securely analyzing sensitive files without sharing them with the GTI community.

#### **`scan_url.py`**

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

### **Public Scanning**

Scripts in this category submit files or URLs to GTI's public analysis endpoints, where results are shared with the GTI community.

#### **`scan_file.py`**

- **Purpose**: Submits a local file to the GTI API for public analysis, polling for completion and retrieving the final threat report.  
    
- **Key Features**:  
    
  - **File Upload**: The script handles the upload of a local file to the GTI API for analysis.  
  - **Dynamic File Sizing**: It intelligently manages both small files (up to 32MB) with a direct upload and larger files (over 32MB) by first obtaining a special upload URL, ensuring a robust and scalable solution.  
  - **Analysis Polling**: After a file is uploaded, the script continuously polls the API to monitor the analysis status, ensuring the final report is not returned until the scanning process is fully completed.  
  - **Final Report**: Upon completion, the script fetches and prints the final analysis report, including the threat verdict (malicious or clean) and the GTI's assessment.  
  - **Robust Error Handling**: The script includes comprehensive error handling to gracefully manage issues such as file not found errors, failed API requests, and invalid responses.


- **API Endpoints Used**:  
    
  - `/files`: Uploads small files (up to 32MB) directly for public scanning.  
  - `/files/upload_url`: Retrieves a special upload URL for large files (\>32MB).  
  - `/analyses/{analysis_id}`: Polls the analysis status for the uploaded file.  
  - `/files/{file_hash}`: Fetches the final threat intelligence report for the scanned file.


- **Use Case**: Analyzing files in a public context to leverage community-driven threat intelligence.

#### **`scan_url.py`**

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

## **Additional Notes**

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


- **API Resources Management**: Both scripts include retry logic for HTTP 429 (rate limit) and 5xx errors. Monitor API usage to stay within your quota, especially during frequent polling.  
    
- **Error Handling**: The scripts handle network failures, invalid responses, and parsing errors, providing clear feedback and retry suggestions. Check console output for error details.  
    
- **Troubleshooting**: Refer to `troubleshooting.md` in the `/docs` folder for help with common issues like API errors, rate limits, or invalid inputs.
