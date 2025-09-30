#========================================================================================
# This script interfaces with the Google Threat Intelligence (GTI) API to retrieve and display
# relationship data for a specified URL. It helps security analysts explore the broader threat
# context by extracting associated threat entities such as malware families, threat actors,
# campaigns, software toolkits, collections, vulnerabilities, and reports.
#
# Output Summary:
# - Displays a well-structured summary of all threat relationships associated with the input URL.
# - Each relationship category (e.g., malware families, campaigns) includes a list of entity IDs and types.
# - Indicates whether data was loaded from cache or freshly fetched from the API.
# - Provides clear error messages and retry suggestions if API calls fail.
#
# Usage:
# - Set your GTI_API_KEY and X_TOOL_HEADER in the configuration section.
# - Replace the example URL in the `main()` function with your target URL.
#========================================================================================

import requests
import json
import os
import base64
from typing import Dict

# API key for Google Threat Intelligence (GTI)
GTI_API_KEY = "YOUR_API_KEY"
# Product name for x-tool header (replace with your actual product name)
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
# Base URL for Google Threat Intelligence API
BASE_URL = "https://www.virustotal.com/api/v3"
# Directory to store cached reports
CACHE_DIR = "cache"

RELATIONSHIPS = (
    "collections,malware_families,related_threat_actors,"
    "software_toolkits,campaigns,reports,vulnerabilities"
)

# Parameters for the API request, including relationships and their attributes
PARAMS = {
    "relationships": RELATIONSHIPS
}

def get_cache_filename(url_id: str) -> str:
    """
    Returns cache file path for the URL relationships.

    Args:
        url_id (str): Encoded URL ID

    Returns:
        str: Cache file path
    """
    return os.path.join(CACHE_DIR, f"url_{url_id}_relationships_cache.json")

def make_api_request(url: str, params: Dict = None) -> Dict:
    """
    Makes a GET request to the GTI API with proper error handling.

    Args:
        url (str): Full API endpoint.
        params (Dict): Query parameters for the request.

    Returns:
        Dict: Result with success flag, data, error message, etc.
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
        print(f"Response status code: {response}")
        result['status_code'] = response.status_code

        if response.status_code == 200:
            result['data'] = response.json()
            result['success'] = True
        elif response.status_code == 400:
            result['error'] = "Bad request - invalid URL or parameters."
        elif response.status_code == 401:
            result['error'] = "Unauthorized - check your API key."
        elif response.status_code == 403:
            result['error'] = "Forbidden - insufficient permissions."
        elif response.status_code == 404:
            result['error'] = "IP address not found."
        elif response.status_code == 429:
            result['error'] = "Rate limit exceeded."
            result['should_retry'] = True
        elif 500 <= response.status_code < 600:
            result['error'] = f"Server error {response.status_code}."
            result['should_retry'] = True
        else:
            result['error'] = f"Unexpected status code: {response.status_code}."

    except requests.exceptions.Timeout:
        result['error'] = "Request timed out."
        result['should_retry'] = True
    except requests.exceptions.ConnectionError:
        result['error'] = "Connection error. Check your internet connection."
        result['should_retry'] = True
    except Exception as e:
        result['error'] = f"Unexpected error: {str(e)}"

    return result

def get_url_relationships(url: str) -> Dict:
    """
    Fetches relationship data from GTI for a given URL, using local cache if available.

    Args:
        url (str): The URL to query.

    Returns:
        Dict: API response including relationship data.
    """
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    except Exception as e:
        return {
            'success': False,
            'error': f"Failed to encode URL: {str(e)}",
            'should_retry': False
        }

    cache_file = get_cache_filename(url_id)

    if os.path.exists(cache_file):
        print(f"Found cached relationship data for URL: {url}")
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            return {'success': True, 'data': data}
        except (IOError, json.JSONDecodeError):
            print("Cache file could not be read. Will refetch from API...")

    print("No cache file found. Fetching relationship data from API...")
    api_url = f"{BASE_URL}/urls/{url_id}"
    print(f"Fetching relationship data for URL: {api_url}")
    response = make_api_request(api_url, PARAMS)

    if response['success']:
        os.makedirs(CACHE_DIR, exist_ok=True)
        try:
            with open(cache_file, 'w') as f:
                json.dump(response['data'], f, indent=2)
            print(f"Cached relationship data at: {cache_file}")
        except IOError as e:
            print(f"Failed to write cache file: {str(e)}")

    return response

def print_relationships(response: Dict, url: str):
    """
    Nicely prints the relationship data from the API response.

    Args:
        response (Dict): The GTI API response containing relationship data.
        url (str): The URL analyzed.
    """
    if not response.get('success'):
        print(f"Error: {response.get('error', 'Unknown error')}")
        if response.get('should_retry'):
            print("Note: This request might succeed if retried later.")
        return

    data = response['data'].get('data', {})
    relationships = data.get('relationships', {})

    if not relationships:
        print(f"No relationships found for URL: {url}")
        return

    print(f"\n=== Relationship Summary for URL: {url} ===")
    for rel_type, rel_data in relationships.items():
        print(f"\n> {rel_type.replace('_', ' ').title()}:")
        items = rel_data.get('data', [])
        if not items:
            print("  - No related entities found.")
        else:
            for item in items:
                print(f"  - ID: {item.get('id', 'N/A')} | Type: {item.get('type', 'N/A')}")

def main():
    # Example URL - replace with your target URL
    url = "https://www.youtube.com"
    print(f"Analyzing URL: {url}")

    url_relationships = get_url_relationships(url)
    if not url_relationships['success'] and url_relationships.get('should_retry'):
        print("Retrying failed request...")
        url_relationships = get_url_relationships(url)
    print_relationships(url_relationships, url)

    print(f"\nAnalysis completed for: {url}")

if __name__ == "__main__":
    main()
