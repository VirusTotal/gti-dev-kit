# ======================================================================================================
# This script retrieves a GTI Augment Widget rendering URL for a given observable (IP, domain,
# URL, or file hash) using the Google Threat Intelligence (GTI) API. The widget allows analysts to embed
# a live, interactive visualization of the observable’s threat context within other platforms.
#
# Output Summary:
# - Embeddable widget URL for threat visualization
# - Contextual messaging in case of failure, including retry suggestions
#
# Usage:
# Set your GTI API key and product name in the `GTI_API_KEY` and `X_TOOL_HEADER` variables.
# Replace the default observable in the `main()` function with the IP, domain, URL, or hash you want to query.
# The script prints a live GTI widget link in the console.
# ======================================================================================================

import requests
from typing import Dict

# API key for Google Threat Intelligence (GTI)
GTI_API_KEY = "YOUR_API_KEY"
# Product name for x-tool header (replace with your actual product name)
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
# Base URL for Google Threat Intelligence API
BASE_URL = "https://www.virustotal.com/api/v3/gtiwidget"

def make_widget_request(observable: str) -> Dict:
    """
    Queries the GTI widget endpoint for the given observable.

    Args:
        observable (str): The IP, domain, URL, or file hash to get widget for.

    Returns:
        dict: API result including success flag, widget data, or error info.
    """
    result = {
        "success": False,
        "data": None,
        "error": None,
        "status_code": None,
        "should_retry": False
    }

    headers = {
        "x-apikey": GTI_API_KEY,
        "x-tool": X_TOOL_HEADER
    }

    try:
        response = requests.get(BASE_URL, headers=headers, params={"query": observable}, timeout=60)
        result["status_code"] = response.status_code

        if response.status_code == 200:
            result["data"] = response.json().get("data", {})
            result["success"] = True
        elif response.status_code == 400:
            result["error"] = "Bad request - the observable may be malformed or unsupported."
        elif response.status_code == 401:
            result["error"] = "Unauthorized - check your API key."
        elif response.status_code == 403:
            result["error"] = "Forbidden - API key not permitted to access widget endpoint."
        elif response.status_code == 429:
            result["error"] = "Rate limit exceeded - retry later."
            result["should_retry"] = True
        elif 500 <= response.status_code < 600:
            result["error"] = f"Server error (HTTP {response.status_code})."
            result["should_retry"] = True
        else:
            result["error"] = f"Unexpected HTTP status: {response.status_code}"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
        result["should_retry"] = True
    except requests.exceptions.RequestException as e:
        result["error"] = f"Request error: {str(e)}"
        result["should_retry"] = True
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"

    return result

def print_widget_info(response: Dict, observable: str) -> None:
    """
    Displays the widget URL.

    Args:
        response (dict): API response from make_widget_request().
        observable (str): The original observable queried.
    """
    if not response.get("success"):
        print(f"\n[!] Failed to retrieve widget for: {observable}")
        print(f"    Error: {response.get('error', 'Unknown error')}")
        if response.get("should_retry"):
            print("    Note: This request might succeed if retried later.")
        return

    data = response.get("data", {})
    # Note: Widget URLs are ephemeral and valid for 3 days.
    print(f"\n=== Widget Info for Observable: {observable} ===")
    print(f"Widget URL       : {data.get('url', 'N/A')}")
    
def main():
    """
    Main function to retrieve widget info for a specific observable.
    """
    # Replace with your test observable (IP, URL, domain, or file hash)
    observable = "1.1.1.1"

    print(f"Requesting GTI Widget for observable: {observable} ...")
    response = make_widget_request(observable)

    if not response["success"] and response.get("should_retry"):
        print("Retrying after failure...")
        response = make_widget_request(observable)

    print_widget_info(response, observable)

if __name__ == "__main__":
    main()
