# ======================================================================================================
# This script provides an interface to the Google Threat Intelligence (GTI) API to search and
# retrieve Attack Surface Management (ASM) issues. ASM helps organizations proactively identify
# vulnerabilities and misconfigurations from an attacker’s perspective.
#
# Output Summary:
# - Indicates whether the search was successful or if an error occurred.
# - Displays the total number of ASM issues matching the query.
# - Prints a formatted JSON representation of the first few (default: 3) issues found.
# - Provides specific error messages and retry guidance for common issues like invalid queries,
#   authorization errors, or API rate limits.
#
# Usage:
# - Set your `GTI_API_KEY` and `X_TOOL_HEADER` values in the configuration section at the top.
# - Customize the `query_string` in the `main()` function to modify filtering parameters (e.g., severity, time).
# - Run the script to perform the ASM issue search and view results.
# ======================================================================================================

import requests
import json
from typing import Dict
from datetime import datetime, timedelta, timezone

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

def search_asm_issues(query_string: str) -> Dict:
    """
    Searches ASM issues using the provided query string with comprehensive error handling.
    
    Args:
        query_string: Query string for filtering ASM issues
        
    Returns:
        Dictionary containing API response with error handling
    """
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    params = {
        "page_size": 1000
    }
    return make_api_request(url, params)


def print_asm_results(response: Dict, max_display: int = 3) -> bool:
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
            return False

        data = response.get('data', {})
        hits = data.get('result', {}).get('hits', [])
        
        if not hits:
            print("No ASM issues found matching the query.")
            return True
    
        print(f"Found {len(hits)} ASM issues (first 3):\n{json.dumps(hits[:max_display], indent=2)}")
        return True
    except Exception as e:
        print(f"Error formatting results: {str(e)}")
        return False

def main():
    """
    Main function to search for ASM issues with severity 5.
    """
    historical_time = datetime.now(timezone.utc) - timedelta(hours=5)
    historical_time_str = historical_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    query_string = f"severity:5 last_seen_after:{historical_time_str}"
    
    print(f"Searching for ASM issues with query: {query_string}")
    
    # Search for ASM issues
    asm_response = search_asm_issues(query_string)
    if not asm_response['success'] and asm_response.get('should_retry'):
        print("\nRetrying failed request...")
        asm_response = search_asm_issues(query_string)
    
    # Print results
    print_asm_results(asm_response)

if __name__ == "__main__":
    main()
