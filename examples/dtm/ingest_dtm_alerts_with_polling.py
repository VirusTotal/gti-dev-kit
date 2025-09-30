# ======================================================================================================
# This script provides an interface to the Google Threat Intelligence (GTI) API to retrieve and
# display alerts from its **Digital Threat Monitoring (DTM)** service. DTM continuously monitors the
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
# - Set your `GTI_API_KEY` and `X_TOOL_HEADER` values in the configuration section at the top.
# - Customize the `params` dictionary in the `poll_dtm_alerts()` function to adjust filters like
#   `size` (number of alerts) or `since` (start date).
# - Run the script to fetch and display the DTM alerts.
# ======================================================================================================

import requests
import time
import json
from typing import Dict, Optional, Any
from datetime import datetime, timedelta, timezone

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
        url: The API endpoint URL
        params: Query parameters for the request
        
    Returns:
        Dictionary containing:
        - success: Boolean indicating success
        - data: Response data if successful
        - error: Error message if failed
        - status_code: HTTP status code
        - should_retry: Boolean indicating if retry is recommended
        - headers: Response headers (for pagination)
    """
    result = {
        'success': False,
        'data': None,
        'error': None,
        'status_code': None,
        'should_retry': False,
        'headers': None
    }
    
    headers = {
        "x-apikey": GTI_API_KEY,
        "x-tool": X_TOOL_HEADER
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=60)
        result['status_code'] = response.status_code
        result['headers'] = response.headers

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
    Fetches DTM alerts from the GTI API with given parameters.
    
    Args:
        params: Query parameters for the API request
        
    Returns:
        Dictionary containing API response with error handling and headers
    """
    url = f"{BASE_URL}/dtm/alerts"
    return make_api_request(url, params)

def parse_next_page_token(headers: Dict[str, str]) -> Optional[str]:
    """
    Parses the 'link' header to extract the next page token if available.
    
    Args:
        headers: HTTP response headers
        
    Returns:
        Next page token string or None if not found
    """
    if not headers or "link" not in headers:
        return None
    link_header = headers["link"]
    # Example format: <https://.../dtm/alerts?page=2>; rel="next"
    for part in link_header.split(","):
        if 'rel="next"' in part:
            url_part = part.split(">")[0].strip("<")
            if "page=" in url_part:
                page_token = url_part.split("page=")[1]
                return page_token
    return None

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
        print(f"Displaying (first {max_display}) alerts:\n{json.dumps(alerts[:max_display], indent=2)}")
        return True
    except Exception as e:
        print(f"Error formatting results: {str(e)}")
        return False

def poll_dtm_alerts(polls: int = 3, interval: int = 5) -> None:
    """
    Polls the DTM alerts endpoint for new alerts with pagination and error handling.
    
    Args:
        polls: Number of polling iterations
        interval: Seconds to wait between polls
    """
    params = {
        "refs": False,
        "size": 100,
        "order": "desc",
        "since": (datetime.now(timezone.utc) - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "monitor_id": [],
        "status": [],
        "alert_type": [],
        "tags": [],
        "match_value": [],
        "severity": [],
        "mscore_gte": 0,
        "search": ""
    }
    
    next_page = None
    new_params = {}

    for i in range(polls):
        print(f"\n=== Poll {i+1}/{polls} ===")
        if next_page:
            new_params["page"] = next_page
            response = list_dtm_alerts(new_params)
        else:
            response = list_dtm_alerts(params)
        
        
        if not response['success'] and response.get('should_retry'):
            print("\nRetrying failed request...")
            response = list_dtm_alerts(params)
        
        print_dtm_results(response)
        
        # Parse next page token from headers for pagination
        next_page = parse_next_page_token(response.get('headers', {}))
        if i < polls - 1:
            print(f"\nWaiting {interval} seconds before next poll...")
            time.sleep(interval)

def main():
    """
    Main function to start DTM alerts polling.
    """
    print("Starting DTM Alerts Polling...")
    poll_dtm_alerts(polls=3, interval=5)

if __name__ == "__main__":
    main()
