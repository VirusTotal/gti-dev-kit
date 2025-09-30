# ======================================================================================================
# This script provides an interface to the Google Threat Intelligence (GTI) API to retrieve and
# display alerts from its Digital Threat Monitoring (DTM) service. DTM continuously monitors the
# deep and dark web for mentions of specified topics, and this script helps security professionals
# to access and review those alerts.
#
# Output Summary:
# - Indicates whether alerts were successfully fetched or if an error occurred.
# - Displays a count of all matching DTM alerts.
# - Prints a formatted JSON representation of the first few (default: 3) alerts found.
# - Provides specific error messages and guidance for common issues like API key errors or
#   rate limits.
#
# Usage:
# - Set your GTI_API_KEY and X_TOOL_HEADER values in the configuration section at the top.
# - Customize the `params` dictionary in the `main()` function to adjust filters like
#   `size` (number of alerts) or `since` (start date).
# - Run the script to fetch and display the DTM alerts.
# ======================================================================================================

import requests
import json
from typing import Dict, Any

# API key for Google Threat Intelligence (GTI)
GTI_API_KEY = "YOUR_API_KEY"
# Product name for x-tool header (replace with your actual product name)
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
# Base URL for Google Threat Intelligence API
BASE_URL = "https://www.virustotal.com/api/v3"

def make_api_request(url: str, params: Dict = None) -> Dict[str, Any]:
    """
    Makes an API request with comprehensive error handling.
    
    Args:
        endpoint: The API endpoint path
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
            result['error'] = "Endpoint not found"
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

def list_dtm_alerts(params: Dict) -> Dict[str, Any]:
    """
    Fetches DTM alerts from the GTI API with comprehensive error handling.
    
    Args:
        params: Query parameters for the API request
        
    Returns:
        Dictionary containing API response with error handling
    """
    url = f"{BASE_URL}/dtm/alerts"
    return make_api_request(url, params)

def print_dtm_results(response: Dict, max_display: int = 3) -> bool:
    """
    Prints DTM alerts results with error handling.
    
    Args:
        response: The API response dictionary
        max_display: Maximum number of alerts to display
        
    Returns:
        True if printed successfully, False otherwise
    """
    try:
        if not response.get('success'):
            print(f"Error fetching DTM alerts: {response.get('error', 'Unknown error')}")
            if response.get('should_retry'):
                print("Note: This request might succeed if retried later.")
            return False

        data = response.get('data', {})
        alerts = data.get('alerts', [])
        
        if not alerts:
            print("No DTM alerts found matching the criteria.")
            return True
    
        print(f"\nFound {len(alerts)} DTM alerts:")
        print(f"Displaying (first {max_display}) alerts:\n{json.dumps(alerts[:3], indent=2)}")
        return True
    except Exception as e:
        print(f"Error formatting results: {str(e)}")
        return False

def main():
    """
    Main function to fetch and display DTM alerts.
    """
    params = {
        "refs": False,
        "size": 100,
        "order": "desc",
        "since": "2025-08-01T00:00:00Z",
        "monitor_id": [],
        "status": [],
        "alert_type": [],
        "tags": [],
        "match_value": [],
        "severity": [],
        "mscore_gte": 0,
        "search": ""
    }
    
    print("\nFetching DTM alerts...")
    
    # Fetch DTM alerts
    dtm_response = list_dtm_alerts(params)
    if not dtm_response['success'] and dtm_response.get('should_retry'):
        print("\nRetrying failed request...")
        dtm_response = list_dtm_alerts(params)
    
    # Print results
    print_dtm_results(dtm_response)

if __name__ == "__main__":
    main()
