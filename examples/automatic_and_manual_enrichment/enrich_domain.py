# ========================================================================================
# This script interfaces with the Google Threat Intelligence (GTI) API to retrieve and 
# display a threat intelligence report for a specified domain name. It assists security 
# analysts and incident responders by providing reputation insights, detection counts, 
# GTI-specific assessments, and metadata related to the domain.
#
# Output Summary:
# - Displays the domain verdict (malicious or clean) based on last analysis statistics.
# - Shows the number of malicious detections flagged by scanning engines.
# - Includes GTI assessment details when available.
# - Provides a direct deep link to the full domain report within the GTI GUI for extended analysis.
# - Indicates whether the result was loaded from local cache or fetched live from the API.
# - Prints the complete JSON report for comprehensive context.
# - Handles API errors and retry suggestions gracefully, including rate limiting and connection issues.
#
# Usage:
# - Set your GTI_API_KEY and X_TOOL_HEADER in the configuration section.
# - Replace the example domain in the `main()` function with your target domain name.
# - Run the script to fetch and display the domain's threat intelligence report.
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

def get_cache_filename(domain: str) -> str:
    """
    Generates a standardized cache filename for a given domain.
    E.g., "cache/domain_www.google.com_cache_file.json"
    """
    return os.path.join(CACHE_DIR, f"domain_{domain}_cache_file.json")

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

def get_domain_report(domain: str) -> Dict:
    """
    Fetches the domain analysis report, using a cache if available.
    """
    cache_file = get_cache_filename(domain)
    if os.path.exists(cache_file):
        print(f"Found cached report for {domain}. Loading from file...")
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            return {'success': True, 'data': cached_data, 'error': None, 'status_code': 200, 'should_retry': False}
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error reading cache file for {domain}: {str(e)}. Proceeding with API call.")

    print(f"No cache file found for {domain}. Fetching data from API...")
    url = f"{BASE_URL}/domains/{domain}"
    api_response = make_api_request(url)
    
    if api_response['success']:
        os.makedirs(CACHE_DIR, exist_ok=True)
        try:
            with open(cache_file, 'w') as f:
                json.dump(api_response['data'], f, indent=2)
            print(f"Successfully saved report to cache file: {cache_file}")
        except IOError as e:
            print(f"Warning: Failed to domain report to cache file: {str(e)}") 
    return api_response

def print_domain_report(domain_report, domain):
    """
    Prints key information from the domain report.
    """
    if not domain_report.get('success'):
        print(f"Error fetching report for {domain}: {domain_report.get('error', 'Unknown error')}")
        if domain_report.get('should_retry'):
            print("Note: This request might succeed if retried later.")
    
    data = domain_report.get('data', {})
    
    try:
        # Print the report
        print(f"\n--- Domain Threat Intelligence Report for {domain} ---")
        print(f"A deep link back to the full report in the GTI user interface: https://www.virustotal.com/gui/domain/{domain}")

        attrs = data.get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        # If the malicious count is greater than 0, it indicates that the domain is considered malicious, as multiple analysis reports have flagged it as such.
        malicious_count = stats.get('malicious', 0)
        verdict = "Malicious" if malicious_count > 0 else "Clean"
        print(f"\nVerdict: {verdict}")
        if malicious_count > 0:
            print(f"Malicious detections: {malicious_count}")
        
        # Print GTI assessment details
        gti_assessment = attrs.get('gti_assessment', {})
        if gti_assessment:
            print(f"\nGTI Assessment:")
            for k, v in gti_assessment.items():
                print(f"  {k}: {v}")
        else:
            print("\nNo GTI assessment available")
        print(f"\n====== Full JSON Report ========\n {json.dumps(data, indent=2)}")
    except Exception as e:
        print(f"Error processing report for {domain}: {str(e)}")

def main():
    domain = "www.google.com"  # The domain to analyze
    print(f"\nStarting analysis for: {domain}")
    
    # 1. Fetch and print the main domain report
    print("\nFetching Domain analysis report...")
    domain_report = get_domain_report(domain)
    if not domain_report['success'] and domain_report.get('should_retry'):
        print("\nRetrying failed request...")
        domain_report = get_domain_report(domain)

    print_domain_report(domain_report, domain)

if __name__ == "__main__":
    main()