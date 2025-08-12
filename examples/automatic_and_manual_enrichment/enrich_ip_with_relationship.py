# ========================================================================================
# This script interfaces with the Google Threat Intelligence (GTI) API to retrieve and 
# display only the relationship data for a specified IP address. It helps security analysts 
# understand the broader threat context by extracting associated threat entities such as 
# malware families, threat actors, campaigns, software toolkits, collections, vulnerabilities, 
# reports, and resolutions.
#
# Output Summary:
# - Displays a well-structured summary of all threat relationships associated with the input IP.
# - Each relationship category (e.g., malware families, campaigns) includes a list of entity IDs and types.
# - Indicates whether data was loaded from cache or freshly fetched from the API.
# - Provides clear error messages and retry suggestions if API calls fail.
#
# Usage:
# - Set your GTI_API_KEY and X_TOOL_HEADER in the configuration section.
# - Replace the example IP in the `main()` function with your target IP address.
# ========================================================================================

import requests
import json
import os
from typing import Dict

# API key for Google Threat Intelligence (GTI)
GTI_API_KEY = "YOUR_API_KEY"
# Product name for x-tool header (replace with your actual product name)
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
# Base URL for Google Threat Intelligence API
BASE_URL = "https://www.virustotal.com/api/v3"
# Directory to store cached reports
CACHE_DIR = "cache"

# Relationships and attributes to request from the API
RELATIONSHIPS = (
    "collections,malware_families,related_threat_actors,"
    "software_toolkits,campaigns,reports,vulnerabilities,resolutions"
)

# Parameters for the API request, including relationships and their attributes
PARAMS = {
    "relationships": RELATIONSHIPS
}

def get_relationship_cache_file(ip_address: str) -> str:
    """
    Returns the file path for the relationship cache of a given IP.

    Args:
        ip_address (str): The IP address.

    Returns:
        str: Cache file path.
    """
    return os.path.join(CACHE_DIR, f"ip_{ip_address}_relationships_cache.json")

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
        result['status_code'] = response.status_code

        if response.status_code == 200:
            result['data'] = response.json()
            result['success'] = True
        elif response.status_code == 400:
            result['error'] = "Bad request - invalid IP address or parameters."
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

def get_ip_relationships(ip_address: str) -> Dict:
    """
    Fetches relationship data from GTI for a given IP, using local cache if available.

    Args:
        ip_address (str): The IP address to query.

    Returns:
        Dict: API response including relationship data.
    """
    cache_file = get_relationship_cache_file(ip_address)

    if os.path.exists(cache_file):
        print(f"Found cached relationship data for {ip_address}")
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            return {'success': True, 'data': data}
        except (IOError, json.JSONDecodeError):
            print("Cache file could not be read. Will refetch from API...")

    print("No cache file found. Fetching relationship data from API...")
    url = f"{BASE_URL}/ip_addresses/{ip_address}"
    print(f"Fetching relationship data for IP: {ip_address}")
    response = make_api_request(url, PARAMS)

    if response['success']:
        os.makedirs(CACHE_DIR, exist_ok=True)
        try:
            with open(cache_file, 'w') as f:
                json.dump(response['data'], f, indent=2)
            print(f"Relationship data cached at: {cache_file}")
        except IOError as e:
            print(f"Failed to write cache file: {str(e)}")

    return response

def print_relationships(response: Dict, ip_address: str):
    """
    Nicely prints the relationship data from the API response.

    Args:
        response (Dict): The GTI API response containing relationship data.
        ip_address (str): The IP address analyzed.
    """
    if not response.get('success'):
        print(f"{response.get('error', 'Unknown error')}")
        return

    data = response['data'].get('data', {})
    relationships = data.get('relationships', {})

    if not relationships:
        print(f"No relationships found for IP: {ip_address}")
        return

    print(f"\n=== Relationship Summary for IP: {ip_address} ===")
    for rel_type, rel_data in relationships.items():
        print(f"\n> {rel_type.replace('_', ' ').title()}:")
        items = rel_data.get('data', [])
        if not items:
            print("  - No related entities found.")
        else:
            for item in items:
                print(f"  - ID: {item.get('id', 'N/A')} | Type: {item.get('type', 'N/A')}")

def main():
    """
    Entry point for the script. Modify the IP address as needed.
    """
    ip_address = "8.8.8.8"  # Replace with your target IP
    print(f"Analyzing IP: {ip_address}")

    ip_relationships = get_ip_relationships(ip_address)
    if not ip_relationships['success'] and ip_relationships.get('should_retry'):
        print("\nRetrying failed request...")
        ip_relationships = get_ip_relationships(ip_address)
    print_relationships(ip_relationships, ip_address)

    print(f"\nAnalysis completed for: {ip_address}")

if __name__ == "__main__":
    main()
