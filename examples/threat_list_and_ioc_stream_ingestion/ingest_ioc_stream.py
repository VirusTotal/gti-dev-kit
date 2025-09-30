# =========================================================================================================
# This script provides an interface to the Google Threat Intelligence (GTI) API to fetch and display
# the latest Indicator of Compromise (IOC) stream objects. It is designed for security analysts and
# threat researchers to obtain real-time curated threat intelligence data.
#
# Output Summary:
# The script prints the total number of new IOCs received along with a formatted JSON snippet of
# the top IOCs, facilitating rapid situational awareness and threat hunting.
#
# Usage:
# Set your GTI API key and product name in the `GTI_API_KEY` and `X_TOOL_HEADER` variables.
# Run the script to fetch the latest IOC stream.
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

def make_api_request(url: str, params: Dict = None) -> Dict[str, Any]:
    """
    Makes an API request to the GTI endpoint with robust error handling.

    Args:
        url: Full API URL to request.
        params: Optional dictionary of query parameters.

    Returns:
        A dictionary containing:
        - success: Boolean indicating if request was successful.
        - data: JSON data if successful.
        - error: Error message if failed.
        - status_code: HTTP response code.
        - should_retry: Boolean suggesting if retry is appropriate.
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

def get_ioc_stream() -> Dict[str, Any]:
    """
    Fetches the latest IOC stream objects from the GTI API.

    Returns:
        Dictionary with success status, data, or error details.
    """
    url = f"{BASE_URL}/ioc_stream"
    return make_api_request(url)

def print_ioc_stream(response: Dict, max_display: int = 3) -> None:
    """
    Prints a summary of the IOC stream response.

    Args:
        response: The response dictionary returned by get_ioc_stream().
        max_display: Maximum number of IOCs to display from the response.
    """
    try:
        if not response.get('success'):
            print(f"Error fetching IOC stream: {response.get('error', 'Unknown error')}")
            if response.get('should_retry'):
                print("This request might succeed if retried later.")
            return

        data = response.get('data', {})
        iocs = data.get('data', [])

        if not iocs:
            print("No new IOCs received.")
            return

        print(f"\nReceived {len(iocs)} new IOCs")
        print(f"Displaying top {min(max_display, len(iocs))} IOCs:")
        print(json.dumps(iocs[:max_display], indent=2))

    except Exception as e:
        print(f"Error printing IOCs: {str(e)}")

def main():
    """
    Main function to initiate a one-time IOC stream fetch.
    Handles retry logic if the first attempt fails and suggests retrying.
    """
    print("Fetching latest IOC stream from Google Threat Intelligence...")
    stream_response = get_ioc_stream()

    if not stream_response['success'] and stream_response.get('should_retry'):
        print("\nRetrying failed request...")
        stream_response = get_ioc_stream()

    print_ioc_stream(stream_response)

if __name__ == "__main__":
    main()
