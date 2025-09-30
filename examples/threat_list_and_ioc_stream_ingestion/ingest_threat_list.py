# =========================================================================================================
# This script provides an interface to the Google Threat Intelligence (GTI) API for fetching and displaying
# curated threat lists. These lists contain structured indicators of compromise (IOCs) across a range of
# threat categories, suitable for SOC teams, incident responders, threat researchers, and automation systems.
#
# Output Summary:
# - Total number of IOCs retrieved per list
# - Formatted preview of the first N indicators (customizable)
# - Error context and retry suggestions when applicable
#
# Usage:
# Set your GTI API key and product name in the `GTI_API_KEY` and `X_TOOL_HEADER` variables.
# Edit the `main()` function to specify the threat list category and (optional) timestamp.
#    - For latest lists: Provide category name only (e.g., "ransomware").
#    - For hourly lists: Also provide timestamp in 'YYYYMMDDHH' format (e.g., "2025021913").
# =========================================================================================================

import requests
import json
from typing import Dict, Any

# API key for Google Threat Intelligence (GTI)
GTI_API_KEY = "YOUR_API_KEY"
# Product name for x-tool header (replace with your actual product name)
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
# Base URL for Google Threat Intelligence API
BASE_URL = "https://www.virustotal.com/api/v3"

def make_api_request(endpoint: str) -> Dict[str, Any]:
    """
    Makes an API request with comprehensive error handling.
    
    Args:
        endpoint: The API endpoint path
        
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
    headers = {
        "x-apikey": GTI_API_KEY,
        "x-tool": X_TOOL_HEADER
    }

    try:
        response = requests.get(url, headers=headers, timeout=60)
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
            result['error'] = "Threat list not found or invalid timestamp"
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

def get_threat_list(list_name: str) -> Dict[str, Any]:
    """
    Fetches the latest threat list from the GTI API with comprehensive error handling.
    
    Args:
        list_name: Name of the threat list (e.g., 'ransomware', 'apt', 'iot')
        
    Returns:
        Dictionary containing API response with error handling
    """   
    url = f"threat_lists/{list_name.lower()}/latest"
    return make_api_request(url)

def get_threat_list_hourly(list_name: str, time_stamp: str) -> Dict[str, Any]:
    """
    Fetches an hourly threat list from the GTI API.

    Args:
        list_name: Name of the threat list.
        time_stamp: A timestamp in YYYYMMDDHH format (e.g., '2025021913').

    Returns:
        Dictionary containing API response with error handling.
    """
    # The URL structure from your reference
    url = f"threat_lists/{list_name.lower()}/{time_stamp}"
    return make_api_request(url)

def print_threat_list(response: Dict, list_name: str, limit: int = 5) -> bool:
    """
    Prints threat list information with error handling.
    
    Args:
        response: The API response dictionary
        list_name: Name of the threat list
        limit: Number of entries to display
        
    Returns:
        True if printed successfully, False otherwise
    """
    if not response.get('success'):
        print(f"Error fetching '{list_name}' threat list: {response.get('error', 'Unknown error')}")
        if response.get('should_retry'):
            print("Note: This request might succeed if retried later.")
        return False

    data = response.get('data', {})
    iocs = data.get('iocs', [])
    
    if not iocs:
        print(f"No IOCs found in the '{list_name}' threat list.")
        return True
    
    try:
        print(f"\n=== Latest {list_name.capitalize()} Threat List ===")
        print(f"Total entries: {len(iocs)}")
        print(f"Displaying (first {limit}) entries:\n{json.dumps(iocs[:limit], indent=2)}")
        
        return True
    except Exception as e:
        print(f"Error processing threat list: {str(e)}")
        return False

def print_hourly_threat_list(response: Dict, list_name: str, time_stamp: str, limit: int = 5) -> bool:
    """
    Prints hourly threat list information with error handling.
    
    Args:
        response: The API response dictionary
        list_name: Name of the threat list
        time_stamp: The timestamp used for the request
        limit: Number of entries to display
        
    Returns:
        True if printed successfully, False otherwise
    """
    if not response.get('success'):
        print(f"Error fetching '{list_name}' threat list for timestamp {time_stamp}: {response.get('error', 'Unknown error')}")
        if response.get('should_retry'):
            print("Note: This request might succeed if retried later.")
        return False

    data = response.get('data', {})
    iocs = data.get('iocs', [])
    
    if not iocs:
        print(f"No IOCs found in the '{list_name}' threat list for timestamp {time_stamp}.")
        return True
    
    try:
        print(f"\n=== {list_name.capitalize()} Threat List for Hour: {time_stamp} ===")
        print(f"Total entries: {len(iocs)}")
        print(f"Displaying (first {limit}) entries:\n{json.dumps(iocs[:limit], indent=2)}")
        
        return True
    except Exception as e:
        print(f"Error processing threat list: {str(e)}")
        return False

def main():
    """
    Main function to fetch and display threat lists.
    """
    # Example for latest threat list
    list_name = "ransomware"
    print(f"Fetching latest '{list_name}' threat list...")
    threat_list_latest = get_threat_list(list_name)
    if not threat_list_latest['success'] and threat_list_latest.get('should_retry'):
        print("\nRetrying failed request...")
        threat_list_latest = get_threat_list(list_name)
    print_threat_list(threat_list_latest, list_name, limit=3)
    
    print("-" * 50)

    # Example for an hourly threat list
    # Use a specific timestamp in 'YYYYMMDDHH' format.
    list_name_hourly = "cryptominer"
    time_stamp_hourly = "2025021913"
    
    print(f"Fetching '{list_name_hourly}' threat list for hour '{time_stamp_hourly}'...")
    threat_list_hourly = get_threat_list_hourly(list_name_hourly, time_stamp_hourly)
    if not threat_list_hourly['success'] and threat_list_hourly.get('should_retry'):
        print("\nRetrying failed request...")
        threat_list_hourly = get_threat_list_hourly(list_name_hourly, time_stamp_hourly)
    print_hourly_threat_list(threat_list_hourly, list_name_hourly, time_stamp_hourly, limit=3)

if __name__ == "__main__":
    main()
