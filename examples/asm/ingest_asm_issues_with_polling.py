# ======================================================================================================
# This script provides an interface to the Google Threat Intelligence (GTI) API for searching
# and polling Attack Surface Management (ASM) issues. ASM simulates an attacker’s viewpoint
# to help organizations proactively identify vulnerabilities and misconfigurations across
# their digital assets.
#
# Output Summary:
# - Indicates whether ASM issues were successfully retrieved or if an error occurred.
# - Displays the count of matching ASM issues per poll.
# - Prints a formatted preview of the first few issues to facilitate rapid review.
#
# Usage:
# - Configure `GTI_API_KEY` and `X_TOOL_HEADER` with your GTI credentials.
# - Customize the `query_string` parameter in `main()` to adjust filtering criteria.
# - Run the script to start polling and viewing ASM issues with periodic updates.
# ======================================================================================================

import time
import requests
import json
from typing import Dict

# API key for Google Threat Intelligence (GTI)
GTI_API_KEY = "YOUR_API_KEY"
# Product name for x-tool header (replace with your actual product name)
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
# Base URL for Google Threat Intelligence API
BASE_URL = "https://www.virustotal.com/api/v3"

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
            result['error'] = "Bad request - invalid query parameters"
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

def search_asm_issues(query_string: str,page_token: str = "") -> Dict:
    """
    Searches ASM issues using the provided query string with comprehensive error handling.
    
    Args:
        query_string: Query string for filtering ASM issues
        
    Returns:
        Dictionary containing API response with error handling
    """
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    params = {
        "page_size": 1000,
        "page_token" : page_token
    }
    return make_api_request(url, params)


def print_asm_results(response: Dict, max_display: int = 3) -> str:
    """
    Prints ASM search results with error handling.
    
    Args:
        response: The API response dictionary
        max_display: Maximum number of issues to display
        
    Returns:
        True if printed successfully, False otherwise
    """
    try:
        if not response.get('success'):
            print(f"Error searching ASM issues: {response.get('error', 'Unknown error')}")
            if response.get('should_retry'):
                print("Note: This request might succeed if retried later.")
            return data.get('result', {}).get('next_page_token', "")

        data = response.get('data', {})
        hits = data.get('result', {}).get('hits', [])
        if not hits:
            print("No ASM issues found matching the query.")
            return True
    
        print(f"Found {len(hits)} ASM issues (first 3):\n{json.dumps(hits[:max_display], indent=2)}")
        return data.get('result', {}).get('next_page_token', "")
    except Exception as e:
        print(f"Error formatting results: {str(e)}")
        return False

def poll_asm_issues(query_string:str,polls: int = 3, interval: int = 5 ) -> None:
    """
    Polls ASM issues for a specified number of polls with a specified interval.
    
    Args:
    polls: Number of polls to perform
    interval: Interval in seconds between polls
    """
    next_cursor = None
    for i in range(polls):
        print(f"\n=== Poll {i+1}/{polls} ===")
        asm_response = search_asm_issues(query_string,next_cursor)
        if not asm_response['success'] and asm_response.get('should_retry'):
            print("\nRetrying failed request...")
            asm_response = search_asm_issues("severity:5")
        next_cursor = print_asm_results(asm_response)
        if i < polls - 1:
            print(f"\nWaiting {interval} seconds before next poll...")
            time.sleep(interval)

def main():
    """
    Main function to search for ASM issues with severity 5.
    """
    query_string = "severity:5"
    print("Starting ASM Issues Polling...")
    poll_asm_issues(query_string,polls=3, interval=5)

if __name__ == "__main__":
    main()
