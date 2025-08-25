# ======================================================================================================
# This script provides an interface to the Google Threat Intelligence (GTI) API for scanning files
# in a private and secure manner. It is designed for security analysts, incident responders, and 
# developers who need to evaluate files for potential threats without public exposure.
#
# Output Summary:
# - Indicates whether the scan was successful or failed.
# - Displays the SHA-256 hash of the scanned file.
# - Prints the malicious/clean verdict based on detection engines.
# - Displays GTI’s custom assessment, if available.
# - Outputs the full scan report in a readable JSON format.
#
# Usage:
# - Set your GTI_API_KEY and X_TOOL_HEADER values at the top of the script.
# - Replace the test file logic in `main()` with your actual file path or integrate this logic
#   into your larger security platform or pipeline.
# - Run the script to securely upload and scan a file using GTI's private file analysis service.
# ======================================================================================================

import json
import requests
import os
import time
from typing import Dict, Optional, Any

# API key for Google Threat Intelligence (GTI)
GTI_API_KEY = "YOUR_API_KEY"
# Product name for x-tool header (replace with your actual product name)
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
# Base URL for Google Threat Intelligence API
BASE_URL = "https://www.virustotal.com/api/v3"

MAX_DIRECT_UPLOAD_SIZE = 32 * 1024 * 1024  # 32MB
POLLING_INTERVAL = 15  # seconds
MAX_POLLING_ATTEMPTS = 20  # ~5 minutes total waiting time

def make_api_request(method: str, endpoint: str, headers: Dict = None, 
                    files: Dict = None, data: Dict = None, 
                    timeout: int = 60) -> Dict[str, Any]:
    """
    Makes an API request with comprehensive error handling.
    
    Args:
        method: HTTP method ('GET', 'POST', etc.)
        endpoint: API endpoint path
        headers: Request headers
        files: Files to upload (for POST requests)
        data: Request payload
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary containing:
        - success: Boolean indicating success
        - data: Response data if successful
        - error: Error message if failed
        - status_code: HTTP status code
        - should_retry: Boolean indicating if retry is recommended
    """
    result = {
        'success': False,
        'data': None,
        'error': None,
        'status_code': None,
        'should_retry': False
    }
    
    url = f"{BASE_URL}/{endpoint}"
    headers = headers or {
        "x-apikey": GTI_API_KEY,
        "x-tool": X_TOOL_HEADER
    }

    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            files=files,
            data=data,
            timeout=timeout
        )
        result['status_code'] = response.status_code

        if response.status_code == 200:
            try:
                result['data'] = response.json()
                result['success'] = True
            except ValueError as e:
                result['error'] = f"Failed to parse JSON response: {str(e)}"
        elif response.status_code == 400:
            result['error'] = "Bad request - invalid parameters"
        elif response.status_code == 401:
            result['error'] = "Unauthorized - invalid API key"
        elif response.status_code == 403:
            result['error'] = "Forbidden - insufficient permissions"
        elif response.status_code == 404:
            result['error'] = "Resource not found"
        elif response.status_code == 429:
            result['error'] = "Rate limit exceeded"
            result['should_retry'] = True
        elif 500 <= response.status_code < 600:
            result['error'] = f"Server error (HTTP {response.status_code})"
            result['should_retry'] = True
        else:
            result['error'] = f"Unexpected HTTP status: {response.status_code}"
    except requests.exceptions.Timeout:
        result['error'] = "Request timed out"
        result['should_retry'] = True
    except requests.exceptions.ConnectionError:
        result['error'] = "Connection error - check your network"
        result['should_retry'] = True
    except requests.exceptions.RequestException as e:
        result['error'] = f"Request failed: {str(e)}"
    except Exception as e:
        result['error'] = f"Unexpected error: {str(e)}"

    return result

def get_upload_url() -> Dict[str, Any]:
    """Get a special upload URL for large files."""
    return make_api_request("GET", "private/files/upload_url")

def upload_file(file_path: str, upload_url: str = None) -> Dict[str, Any]:
    """
    Uploads a file for scanning, handling both direct and large file uploads.
    
    Args:
        file_path: Path to the file to upload
        upload_url: Special upload URL for large files (None for direct upload)
    """
    endpoint = "private/files" if upload_url is None else upload_url.replace(BASE_URL + '/', '')
    
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
            return make_api_request("POST", endpoint, files=files)
    except FileNotFoundError:
        return {
            'success': False,
            'error': f"File not found: {file_path}",
            'should_retry': False
        }
    except Exception as e:
        return {
            'success': False,
            'error': f"File upload failed: {str(e)}",
            'should_retry': True
        }

def poll_analysis_status(analysis_id: str) -> Dict[str, Any]:
    """
    Polls for analysis completion status.
    
    Args:
        analysis_id: The analysis ID to poll
    """
    for attempt in range(MAX_POLLING_ATTEMPTS):
        result = make_api_request("GET", f"private/analyses/{analysis_id}")
        
        if not result['success']:
            return result
        
        status = result['data'].get('data', {}).get('attributes', {}).get('status', '')
        print(f"Polling attempt {attempt + 1}/{MAX_POLLING_ATTEMPTS}: Status = {status}")
        if status == "completed":
            return result
        elif status in ["error", "unsupported file type", "corrupted file"]:
            return {
                'success': False,
                'error': f"Analysis {status}",
                'should_retry': False
            }
        
        if attempt < MAX_POLLING_ATTEMPTS - 1:
            time.sleep(POLLING_INTERVAL)
    
    return {
        'success': False,
        'error': "Max polling attempts reached",
        'should_retry': True
    }

def get_file_report(file_hash: str) -> Dict[str, Any]:
    """Retrieves the final file analysis report."""
    return make_api_request("GET", f"private/files/{file_hash}")

def scan_private_file_and_get_report(file_path: str) -> Optional[Dict]:
    """
    Uploads and scans a private file with comprehensive error handling.
    
    Args:
        file_path: Path to the file to scan
        
    Returns:
        The final scan report if successful, None otherwise
    """
    try:
        # Validate file
        if not os.path.exists(file_path):
            print(f"Error: File not found at {file_path}")
            return None
        
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            print("Error: File is empty")
            return None

        # Determine upload method
        upload_url = None
        if file_size > MAX_DIRECT_UPLOAD_SIZE:
            print("File is large (>32MB), getting special upload URL...")
            upload_url_resp = get_upload_url()
            if not upload_url_resp['success']:
                print(f"Error getting upload URL: {upload_url_resp['error']}")
                return None
            upload_url = upload_url_resp['data'].get('data', '')
            if not upload_url:
                print("Error: Empty upload URL received")
                return None 
            
        # Upload file
        print("Uploading file for scanning...")
        upload_result = upload_file(file_path, upload_url)
        if not upload_result['success']:
            print(f"Error uploading file: {upload_result['error']}")
            if upload_result['should_retry']:
                print("Retrying upload...")
                upload_result = upload_file(file_path, upload_url)
                if not upload_result['success']:
                    print(f"Upload failed again: {upload_result['error']}")
                    return None
            else:
                return None

        # Get analysis ID
        analysis_id = upload_result['data'].get('data', {}).get('id', '')
        if not analysis_id:
            print("Error: No analysis ID received")
            return None

        # Poll for analysis completion
        print(f"Analysis started (ID: {analysis_id}), polling for results...")
        poll_result = poll_analysis_status(analysis_id)
        if not poll_result['success']:
            print(f"Error during analysis: {poll_result['error']}")
            return None

        # Get final report
        file_hash = poll_result['data'].get('meta', {}).get('file_info', {}).get('sha256', '')
        if not file_hash:
            print("Error: No file hash received")
            return None

        print("Analysis completed, retrieving final report...")
        report_result = get_file_report(file_hash)
        if not report_result['success']:
            print(f"Error retrieving report: {report_result['error']}")
            return None
        return report_result["data"]

    except Exception as e:
        print(f"Unexpected error during scanning: {str(e)}")
        return None

def print_scan_report(report: Dict) -> None:
    """Prints the scan report in a human-readable format."""
    if not report or 'data' not in report:
        print("Invalid or empty scan report")
        return

    data = report['data']
    attrs = data.get('attributes', {})
    stats = attrs.get('last_analysis_stats', {})

    # Basic info
    print("\n--- Scan Report ---")
    print(f"File SHA-256: {data.get('id', 'N/A')}")
    
    # If the malicious count is greater than 0, it indicates that the File is considered malicious, as multiple analysis reports have flagged it as such.
    malicious = stats.get('malicious', 0)
    verdict = "MALICIOUS" if malicious > 0 else "CLEAN"
    print(f"\nVerdict: {verdict}")
    if malicious > 0:
        print(f"Malicious detections: {malicious}")

    # GTI Assessment
    gti_assessment = attrs.get('gti_assessment', {})
    if gti_assessment:
        print("\nGTI Assessment:")
        for k, v in gti_assessment.items():
            print(f"  {k}: {v}")
    print(f"\n====== Full JSON Report ========\n {json.dumps(data, indent=2)}")
    
def main():
    """Main function to handle file scanning and behavior analysis."""

    # Create a dummy file for demonstration
    file_path = "dummy_private_file.txt"
    with open(file_path, "w") as f:
        f.write("11111")
    print(f"Created test file: {file_path}")

    print(f"\nScanning file: {file_path}")
    scan_result = scan_private_file_and_get_report(file_path)
    
    if scan_result:
        print("\nScan completed successfully!")
        print_scan_report(scan_result)
    else:
        print("\nScan failed or no results available")

if __name__ == "__main__":
    main()
