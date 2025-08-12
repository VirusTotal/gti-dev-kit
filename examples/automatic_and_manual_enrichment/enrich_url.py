# ======================================================================================================
# This script interfaces with the Google Threat Intelligence (GTI) API to retrieve and display
# a threat intelligence report for a specified URL. It assists security analysts in evaluating
# the reputation, risk level, and security posture of the URL based on GTI assessments and
# detection statistics from various security vendors.
#
# Output Summary:
# - Displays a verdict (malicious or clean) based on GTI assessment and detection counts.
# - Provides the number of malicious detections from the last analysis.
# - Includes a deep link to the full report in the GTI graphical user interface.
# - Prints the complete JSON threat report for further inspection.
# - Indicates whether the result was loaded from cache or fetched live from the GTI API.
# - Clearly reports errors and advises when retrying is appropriate.
#
# Usage:
# - Set your GTI_API_KEY and X_TOOL_HEADER values in the configuration section.
# - Replace the example URL in the `main()` function with the URL you want to analyze.
# - Run the script to fetch and display the URL's threat intelligence report.
# ======================================================================================================

import requests
import json
import os
import base64
from typing import Dict

# API key for Google Threat Intelligence (GTI)
GTI_API_KEY = "YOUR_API_KEY"
# Product name for x-tool header (replace with your actual product name)
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
# Base URL for Google Threat Intelligence API
BASE_URL = "https://www.virustotal.com/api/v3"

# Directory to store cached reports
CACHE_DIR = "cache"


def get_cache_filename(url_id: str) -> str:
    """
    Generates a standardized cache filename for a given URL ID.
    E.g., "cache/url_aHR0cHM6Ly93d3cueW91dHViZS5jb20_cache_file.json"
    """
    return os.path.join(CACHE_DIR, f"url_{url_id}_cache_file.json")

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
            result['error'] = "Bad request - invalid URL or parameters"
        elif response.status_code == 401:
            result['error'] = "Unauthorized - invalid API key"
        elif response.status_code == 403:
            result['error'] = "Forbidden - insufficient permissions"
        elif response.status_code == 404:
            result['error'] = "URL not found in the database"
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

def get_url_report(url: str) -> Dict:
    """
    Fetches the URL analysis report, using a cache if available.
    
    Args:
        url: The URL to analyze
        
    Returns:
        API response dictionary with error handling
    """
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    except Exception as e:
        return {
            'success': False,
            'error': f"Failed to encode URL: {str(e)}",
            'should_retry': False
        }

    cache_file = get_cache_filename(url_id)
    
    # Check if a cached file exists
    if os.path.exists(cache_file):
        print(f"Found cached URL report for {url}. Loading from file...")
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            return {'success': True, 'data': cached_data, 'error': None, 'status_code': 200, 'should_retry': False}
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error reading cache file for {url}: {str(e)}. Proceeding with API call.")

    # If no cache or error, make API call
    print(f"No cache file found for {url}. Fetching URL report from API...")
    api_url = f"{BASE_URL}/urls/{url_id}"
    api_response = make_api_request(api_url)

    # If API call is successful, save the response to the cache
    if api_response['success']:
        os.makedirs(CACHE_DIR, exist_ok=True)
        try:
            with open(cache_file, 'w') as f:
                json.dump(api_response['data'], f, indent=2)
            print(f"Successfully saved URL report for {url} to cache file: {cache_file}")
        except IOError as e:
            print(f"Warning: Failed to save URL report to cache file: {str(e)}")
        
    return api_response

def print_url_report(report: Dict, url: str) -> bool:
    """
    Prints formatted URL report with error handling.
    
    Args:
        report: The report data dictionary
        url: The URL being analyzed
        
    Returns:
        True if printed successfully, False otherwise
    """
    if not report.get('success'):
        print(f"Error fetching report for {url}: {report.get('error', 'Unknown error')}")
        if report.get('should_retry'):
            print("Note: This request might succeed if retried later.")

    data = report.get('data', {})
    
    try:
        print(f"\n--- URL Threat Intelligence Report for {url} ---")
        print(f"A deep link back to the full report in the GTI user interface: https://www.virustotal.com/gui/url/{base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")}")

        # Basic info
        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        
        # If the malicious count is greater than 0, it indicates that the URL is considered malicious, as multiple analysis reports have flagged it as such.
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
    # Default URL (YouTube)
    url = "https://www.youtube.com/"
    
    print(f"\nStarting analysis for: {url}")
    
    # Get and print URL report
    print("\nFetching URL analysis report...")
    url_report = get_url_report(url)
    if not url_report['success'] and url_report.get('should_retry'):
        print("Retrying failed request...")
        url_report = get_url_report(url)
    
    print_url_report(url_report, url)

if __name__ == "__main__":
    main()
