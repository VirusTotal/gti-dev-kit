# ==========================================================================================================
# This script provides an interface to the Google Threat Intelligence (GTI) API for fetching
# and polling the IOC (Indicator of Compromise) Stream. This service represents an evolution
# of the previous Livehunt functionality, consolidating IOC matches from various sources into
# a single, actionable feed based on your custom interests.
#
# Output Summary:
# The script polls the GTI IOC stream endpoint to fetch and display newly published IOCs.
# It uses cursor-based pagination to track progress and prevent duplication across polling cycles.
# It includes robust error handling for API, network, and parsing errors, with retry suggestions.
# The output displays up to three IOCs per poll and supports configurable polling intervals and counts.
#
# Usage:
# Set your GTI API key and product name in the `GTI_API_KEY` and `X_TOOL_HEADER` variables.
# Adjust the polling count and interval as needed in the `poll_ioc_stream` function call.
# Run the script to start continuous IOC stream monitoring.
# ==========================================================================================================

import requests
import time
import json
from typing import Dict, Optional, Any

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

def get_ioc_stream_objects(cursor: Optional[str] = None) -> Dict[str, Any]:
    """
    Fetches IOC stream objects from the GTI API with comprehensive error handling.
    
    Args:
        cursor: Cursor for pagination to fetch new objects since last poll
        
    Returns:
        Dictionary containing API response with error handling
    """
    params = {}
    url = f"{BASE_URL}/ioc_stream"
    if cursor:
        params["cursor"] = cursor
    
    return make_api_request(url, params)


def print_ioc_stream(response: Dict, max_display: int = 3) -> Optional[str]:
    """
    Processes IOC stream response and returns next cursor.
    
    Args:
        response: The API response dictionary
        max_display: Maximum number of IOCs to display
        
    Returns:
        Next cursor value if available, None otherwise
    """
    try:
        if not response.get('success'):
            print(f"Error fetching IOC stream: {response.get('error', 'Unknown error')}")
            if response.get('should_retry'):
                print("Note: This request might succeed if retried later.")
            return None

        data = response.get('data', {})
        iocs = data.get('data', [])
        
        if not iocs:
            print("No new IOCs received in this poll.")
            return data.get('meta', {}).get('next_cursor')
    
        print(f"\nReceived {len(iocs)} new IOCs:")
        print(f"Displaying (first 3) IOCs:\n{json.dumps(iocs[:max_display], indent=2)}")
    
        
        return data.get('meta', {}).get('next_cursor')
    except Exception as e:
        print(f"Error processing IOCs: {str(e)}")
        return None

def poll_ioc_stream(polls: int = 3, interval: int = 5) -> None:
    """
    Polls the IOC stream endpoint for new IOCs with comprehensive error handling.
    
    Args:
        polls: Number of polling iterations
        interval: Seconds to wait between polls
    """
    current_cursor = None
    
    for i in range(polls):
        print(f"\n=== Poll {i+1}/{polls} ===")
        
        # Get IOC stream data
        stream_response = get_ioc_stream_objects(current_cursor)
        
        # Process response and get next cursor
        current_cursor = print_ioc_stream(stream_response)
        
        # Don't sleep after last iteration
        if i < polls - 1:
            print(f"\nWaiting {interval} seconds before next poll...")
            time.sleep(interval)

def main():
    """
    Main function to start IOC stream polling.
    """
    print("Starting IOC Stream Polling...")
    poll_ioc_stream(polls=3, interval=5)

if __name__ == "__main__":
    main()
