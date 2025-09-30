# ==========================================================================================================
# This script provides an interface to the Google Threat Intelligence (GTI) API for fetching and polling
# curated hourly threat lists. These threat lists contain Indicators of Compromise (IOCs) organized by
# category and timestamp, enabling security analysts to monitor evolving threats on an hourly basis.
#
# Output Summary:
# - Prints concise, timestamped threat list reports.
# - Displays total IOC count and sample indicators per poll.
# - Provides error context and retry suggestions where applicable.
#
# Usage:
# Set your GTI API key and product name in the `GTI_API_KEY` and `X_TOOL_HEADER` variables.
# Edit the `main()` function to specify:
#   - The threat list category to poll (e.g., "cryptominer").
#   - Number of polls (`polls`) and polling interval in seconds (`interval`).
# Run the script to fetch and display hourly threat lists for the specified parameters.
# ==========================================================================================================

import requests
import json
import time
from datetime import datetime, timedelta, timezone
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

def get_threat_list_hourly(list_name: str, time_stamp: str) -> Dict[str, Any]:
    """
    Fetches an hourly threat list from the GTI API.
    """
    url = f"threat_lists/{list_name.lower()}/{time_stamp}"
    return make_api_request(url)

def print_hourly_threat_list(response: Dict, list_name: str, time_stamp: str, limit: int = 5) -> bool:
    """
    Prints hourly threat list information with error handling.
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

def poll_hourly_threat_lists(list_name: str, polls: int = 5, interval: int = 5) -> None:
    """
    Polls the hourly threat list endpoint starting from (UTC now - polls),
    increasing 1 hour each time.
    """
    start_time = datetime.now(timezone.utc) - timedelta(hours=polls)

    print(f"\nStarting polling at: {start_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"Polling '{list_name}' threat list for {polls} hours...\n")

    for i in range(polls):
        poll_time = start_time + timedelta(hours=i)
        timestamp = poll_time.strftime("%Y%m%d%H")

        print(f"\n=== Poll {i + 1}/{polls} | Timestamp: {timestamp} ===")
        response = get_threat_list_hourly(list_name, timestamp)

        if not response['success'] and response.get('should_retry'):
            print("Request failed. Retrying...\n")
            response = get_threat_list_hourly(list_name, timestamp)

        print_hourly_threat_list(response, list_name, timestamp, limit=3)

        if i < polls - 1:
            print(f"\n Waiting {interval} seconds before next poll...")
            time.sleep(interval)

def main():
    """
    Main function to fetch and display threat lists.
    """
    # Old direct fetch for single hour:
    list_name_hourly = "cryptominer"

    # New: Stream-style polling for last 5 hours
    print("\n\n------ Threat List Hourly Polling -----")
    poll_hourly_threat_lists(list_name_hourly, polls=5, interval=5)

if __name__ == "__main__":
    main()
