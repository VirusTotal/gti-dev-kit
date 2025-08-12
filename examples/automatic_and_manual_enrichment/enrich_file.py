# ========================================================================================
# This script interfaces with the Google Threat Intelligence (GTI) API to retrieve and 
# display a threat intelligence report for a specific file hash (SHA-256, SHA-1, or MD5).
# It supports malware analysts and incident responders by providing verdicts, detection
# counts, GTI assessments, and metadata tied to the file.
#
# Output Summary:
# - Displays the verdict (malicious or clean) based on last analysis stats.
# - Shows the number of malicious detections from scanning engines.
# - Includes GTI assessment details when available.
# - Provides a direct deep link to the full file report in the GTI GUI.
# - Indicates whether the result was loaded from cache or fetched live from the API.
# - Prints the complete JSON report for full context.
# - Handles API errors and retry suggestions gracefully.
#
# Usage:
# - Set your GTI_API_KEY and X_TOOL_HEADER in the configuration section.
# - Replace the example hash in the `main()` function with the file hash you want to analyze.
# - Run the script to fetch and display the file's threat intelligence report.
# ========================================================================================

import requests
import json
import os
from typing import Dict

# API key for Google Threat Intelligence (GTI)
GTI_API_KEY = "YOUR_API_KEY"
# Product name for x-tool header (replace with your actual product name)
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
# Base URL for Google Threat Intelligence API
BASE_URL = "https://www.virustotal.com/api/v3"

# Directory to store cached reports
CACHE_DIR = "cache"

def get_cache_filename(file_hash: str) -> str:
    """
    Generates a standardized cache filename for a given file hash and report type.
    E.g., "cache/file_0078c813..._cache_file.json"
    """
    return os.path.join(CACHE_DIR, f"file_{file_hash}_cache_file.json")

def make_api_request(url: str, params: Dict = None) -> Dict:
    """
    Makes an API request with comprehensive error handling.
    
    Args:
        url: The API endpoint URL
        params: Query parameters for the request
        
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
    
    headers = {
        "x-apikey": GTI_API_KEY,
        "x-tool": X_TOOL_HEADER
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=60)
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

def get_file_report(file_hash: str) -> Dict:
    """
    Fetches the file analysis report, using a cache if available.
    
    Args:
        file_hash: The file hash to query
        
    Returns:
        API response dictionary with error handling
    """
    cache_file = get_cache_filename(file_hash)
    
    # Check if a cached file exists
    if os.path.exists(cache_file):
        print(f"Found cached file report for {file_hash}. Loading from file...")
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            return {'success': True, 'data': cached_data, 'error': None, 'status_code': 200, 'should_retry': False}
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error reading cache file for {file_hash}: {str(e)}. Proceeding with API call.")

    # If no cache or error, make API call
    print(f"No cache file found for {file_hash}. Fetching file report from API...")
    url = f"{BASE_URL}/files/{file_hash}"
    api_response = make_api_request(url)
    
    # If API call is successful, save the response to the cache
    if api_response['success']:
        os.makedirs(CACHE_DIR, exist_ok=True)
        try:
            with open(cache_file, 'w') as f:
                json.dump(api_response['data'], f, indent=2)
            print(f"Successfully saved file report for {file_hash} to cache file: {cache_file}")
        except IOError as e:
            print(f"Warning: Failed to save file report to cache file: {str(e)}")
        
    return api_response

def print_file_report(report: Dict, file_hash: str) -> bool:
    """
    Prints formatted file report with error handling.
    
    Args:
        report: The report data dictionary
        file_hash: The file hash being analyzed
        
    Returns:
        True if printed successfully, False otherwise
    """
    if not report.get('success'):
        print(f"Error fetching report for {file_hash}: {report.get('error', 'Unknown error')}")
        if report.get('should_retry'):
            print("Note: This request might succeed if retried later.")

    data = report.get('data', {})
    
    try:
        print(f"\n--- File Threat Intelligence Report for {file_hash} ---")
        print(f"A deep link back to the full report in the GTI user interface: https://www.virustotal.com/gui/file/{file_hash}")
        
        # Basic info
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        
        # If the malicious count is greater than 0, it indicates that the file is considered malicious, as multiple analysis reports have flagged it as such.
        malicious_count = stats.get('malicious', 0)
        verdict = "MALICIOUS" if malicious_count > 0 else "CLEAN"
        print(f"\nVerdict: {verdict}")
        if malicious_count > 0:
            print(f"Malicious detections: {malicious_count}")

        # GTI Assessment
        gti_assessment = attrs.get('gti_assessment', {})
        if gti_assessment:
            print("\nGTI Assessment:")
            for k, v in gti_assessment.items():
                print(f"  {k}: {v}")  
        
        print(f"\n====== Full JSON Report ========\n {json.dumps(data, indent=2)}")
    except Exception as e:
        print(f"Error processing report: {str(e)}")
   
def main():
    # Default sample hash (replace with your own)
    file_hash = "0078c8132fb99b4bccbb2e2429885a857d6a89534f74e23e6a12821abd2c3db2"
    
    print(f"\nStarting analysis for: {file_hash}")

    # Get and print file report
    print("\nFetching File analysis report...")
    file_report = get_file_report(file_hash)
    if not file_report['success'] and file_report.get('should_retry'):
        print("Retrying failed request...")
        file_report = get_file_report(file_hash)
    
    print_file_report(file_report, file_hash)

if __name__ == "__main__":
    main()
