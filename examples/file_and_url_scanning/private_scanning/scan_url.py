# ======================================================================================================
# This script provides an interface to the Google Threat Intelligence (GTI) API for scanning URLs in a
# private environment. It enables security professionals to submit URLs for analysis, monitor the scan
# progress, and retrieve detailed verdicts and GTI assessments without exposing data publicly.
#
# Output Summary:
# - Indicates whether the scan was completed successfully or encountered an error.
# - Displays the malicious/clean verdict and the number of detection engines that flagged the URL.
# - Prints GTI’s assessment details if available.
# - Provides the full scan report in formatted JSON for manual inspection.
#
# Usage:
# - Set your GTI_API_KEY and X_TOOL_HEADER values at the top of the script.
# - Replace the default demo URL in the `main()` function with the URL you want to scan.
# - Run the script to submit, scan, and retrieve the verdict for any URL in a secure, non-public workflow.
# ======================================================================================================

import json
import requests
import time
from typing import Dict, Optional, Any

# API key for Google Threat Intelligence (GTI)
GTI_API_KEY = "YOUR_API_KEY"
# Product name for x-tool header (replace with your actual product name)
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
# Base URL for Google Threat Intelligence API
BASE_URL = "https://www.virustotal.com/api/v3"

POLLING_INTERVAL = 15  # seconds
MAX_POLLING_ATTEMPTS = 20  # ~5 minutes total waiting time

def make_api_request(method: str, endpoint: str, headers: Dict = None, 
                    data: Dict = None, timeout: int = 60) -> Dict[str, Any]:
    """
    Makes an API request with comprehensive error handling.
    
    Args:
        method: HTTP method ('GET', 'POST', etc.)
        endpoint: API endpoint path
        headers: Request headers
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
        "x-tool": X_TOOL_HEADER,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        response = requests.request(
            method,
            url,
            headers=headers,
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
            result['error'] = "Bad request - invalid URL or parameters"
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

def submit_url_for_scanning(url: str) -> Dict[str, Any]:
    """
    Submits a URL for scanning.
    
    Args:
        url: The URL to scan
        
    Returns:
        API response with analysis ID if successful
    """
    payload = {"url": url}
    return make_api_request("POST", "private/urls", data=payload)

def poll_analysis_status(analysis_id: str) -> Dict[str, Any]:
    """
    Polls for analysis completion status.
    
    Args:
        analysis_id: The analysis ID to poll
        
    Returns:
        API response with URL ID if analysis completed
    """
    for attempt in range(MAX_POLLING_ATTEMPTS):
        result = make_api_request("GET", f"private/analyses/{analysis_id}")
        
        if not result['success']:
            return result
        
        status = result['data'].get('data', {}).get('attributes', {}).get('status', '')
        print(f"Polling attempt {attempt + 1}/{MAX_POLLING_ATTEMPTS}: Status = {status}")
        if status == "completed":
            url_id = result['data'].get('meta', {}).get('url_info', {}).get('id', '')
            if url_id:
                return {
                    'success': True,
                    'data': {'url_id': url_id}
                }
            return {
                'success': False,
                'error': "No URL ID found in completed analysis",
                'should_retry': False
            }
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

def get_url_report(url_id: str) -> Dict[str, Any]:
    """
    Retrieves the final URL scan report.
    
    Args:
        url_id: The URL ID to get report for
        
    Returns:
        API response with scan results
    """
    return make_api_request("GET", f"private/urls/{url_id}")

def scan_private_url_and_get_report(url: str) -> Optional[Dict]:
    """
    Scans a private URL with comprehensive error handling.
    
    Args:
        url: The URL to scan
        
    Returns:
        The scan report if successful, None otherwise
    """
    try:
        # Submit URL for scanning
        print(f"Submitting URL for scanning: {url}")
        submit_result = submit_url_for_scanning(url)
        if not submit_result['success']:
            print(f"Error submitting URL: {submit_result['error']}")
            if submit_result['should_retry']:
                print("Retrying submission...")
                submit_result = submit_url_for_scanning(url)
                if not submit_result['success']:
                    print(f"Submission failed again: {submit_result['error']}")
                    return None
            else:
                return None

        # Get analysis ID
        analysis_id = submit_result['data'].get('data', {}).get('id', '')
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
        url_id = poll_result['data'].get('url_id', '')
        if not url_id:
            print("Error: No URL ID received")
            return None

        print("Analysis completed, retrieving final report...")
        report_result = get_url_report(url_id)
        if not report_result['success']:
            print(f"Error retrieving report: {report_result['error']}")
            return None

        return report_result['data']

    except Exception as e:
        print(f"Unexpected error during scanning: {str(e)}")
        return None

def print_scan_report(report: Dict) -> None:
    """Prints the URL scan report in a human-readable format."""
    if not report or 'data' not in report:
        print("Invalid or empty scan report")
        return

    data = report['data']
    attrs = data.get('attributes', {})
    stats = attrs.get('last_analysis_stats', {})

    # Basic info
    print("\n=== URL Scan Report ===")

    # If the malicious count is greater than 0, it indicates that the URL is considered malicious, as multiple analysis reports have flagged it as such.
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
    """Main function to handle URL scanning."""

    # Default URL for demonstration
    url = "https://www.youtube.com/"
    print(f"Using default URL: {url}")

    print(f"\nScanning URL: {url}")
    scan_result = scan_private_url_and_get_report(url)
    
    if scan_result:
        print("\nScan completed successfully!")
        print_scan_report(scan_result)
    else:
        print("\nScan failed or no results available")

if __name__ == "__main__":
    main()
