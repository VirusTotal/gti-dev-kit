# ======================================================================================================
# This script interfaces with the Google Threat Intelligence (GTI) API to retrieve and display
# a threat intelligence report for a specified IP address. It helps security analysts assess
# the risk level and associations of an IP by presenting threat verdicts, location metadata,
# GTI assessments, and more.
#
# Output Summary:
# - Displays the verdict (malicious or clean) based on detection stats.
# - Shows the number of malicious detections from the last analysis.
# - Prints IP metadata such as country, ASN, and network details.
# - Includes GTI assessment values when available.
# - Provides a direct deep link to the full IP report in the GTI user interface.
# - Indicates whether the data was loaded from cache or fetched live from the API.
# - Displays the complete JSON threat report for deeper inspection.
# - Clearly reports errors and retry suggestions in case of failures.
#
# Usage:
# - Set your GTI_API_KEY and X_TOOL_HEADER in the configuration section.
# - Replace the default IP in the `main()` function with the target IP address.
# - Run the script to fetch and display the IP's threat intelligence report.
# ======================================================================================================

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

def get_cache_filename(ip_address: str) -> str:
    """
    Generates a standardized cache filename for a given ip.
    E.g., "cache/ip_www.google.com_cache_file.json"
    """
    return os.path.join(CACHE_DIR, f"ip_{ip_address}_cache_file.json")

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
            result['error'] = "Bad request - invalid IP address or parameters"
        elif response.status_code == 401:
            result['error'] = "Unauthorized - invalid API key"
        elif response.status_code == 403:
            result['error'] = "Forbidden - insufficient permissions"
        elif response.status_code == 404:
            result['error'] = "IP address not found in the database"
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

def get_ip_report(ip_address: str) -> Dict:
    """
    Fetches the IP analysis report, using a cache if available.
    
    Args:
        ip_address: The IP address to query
        
    Returns:
        API response dictionary with error handling
    """
    cache_file = get_cache_filename(ip_address)
    
    # Check if a cached file exists
    if os.path.exists(cache_file):
        print(f"Found cached IP report for {ip_address}. Loading from file...")
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            return {'success': True, 'data': cached_data, 'error': None, 'status_code': 200, 'should_retry': False}
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error reading cache file for {ip_address}: {str(e)}. Proceeding with API call.")

    # If no cache or error, make API call
    print(f"No cache file found for {ip_address}. Fetching IP report from API...")
    url = f"{BASE_URL}/ip_addresses/{ip_address}"
    api_response = make_api_request(url)
    
    # If API call is successful, save the response to the cache
    if api_response['success']:
        os.makedirs(CACHE_DIR, exist_ok=True)
        try:
            with open(cache_file, 'w') as f:
                json.dump(api_response['data'], f, indent=2)
            print(f"Successfully saved IP report for {ip_address} to cache file: {cache_file}")
        except IOError as e:
            print(f"Warning: Failed to save IP report to cache file: {str(e)}")
    return api_response

def print_ip_report(report: Dict, ip_address: str) -> bool:
    """
    Prints formatted IP report with error handling.
    
    Args:
        report: The report data dictionary
        ip_address: The IP address being analyzed
        
    Returns:
        True if printed successfully, False otherwise
    """
    if not report.get('success'):
        print(f"Error fetching report for {ip_address}: {report.get('error', 'Unknown error')}")
        if report.get('should_retry'):
            print("Note: This request might succeed if retried later.")

    data = report.get('data', {})
    
    try:
        print(f"\n--- IP Address Threat Intelligence Report for {ip_address} ---")
        print(f"A deep link back to the full report in the GTI user interface: https://www.virustotal.com/gui/ip-address/{ip_address}")
        
        # Basic info
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        
        # If the malicious count is greater than 0, it indicates that the IP is considered malicious, as multiple analysis reports have flagged it as such.
        malicious_count = stats.get('malicious', 0)
        verdict = "MALICIOUS" if malicious_count > 0 else "CLEAN"
        print(f"\nVerdict: {verdict}")
        if malicious_count > 0:
            print(f"Malicious detections: {malicious_count}")

        # Location info
        print("\nLocation Information:")
        print(f"Country: {attrs.get('country', 'Unknown')}")
        print(f"ASN: {attrs.get('asn', 'Unknown')}")
        print(f"Network: {attrs.get('network', 'Unknown')}")
        
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
    # Default IP (Google DNS)
    ip_address = "8.8.8.8"
    
    print(f"\nStarting analysis for: {ip_address}")
    
    # Get and print IP report
    print("\nFetching IP analysis report...")
    ip_report = get_ip_report(ip_address)
    if not ip_report['success'] and ip_report.get('should_retry'):
        print("Retrying failed request...")
        ip_report = get_ip_report(ip_address)
    
    print_ip_report(ip_report, ip_address)
if __name__ == "__main__":
    main()
