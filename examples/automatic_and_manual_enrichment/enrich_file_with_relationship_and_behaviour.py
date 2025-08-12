# ========================================================================================
# This script interfaces with the Google Threat Intelligence (GTI) API to retrieve and 
# display only the relationship data for a specified File. It helps security analysts 
# understand the broader threat context by extracting associated threat entities such as 
# malware families, threat actors, campaigns, software toolkits, collections, vulnerabilities 
# and reports.it provide mitre data and sandbox behaviour data.
#
# Output Summary:
# - Displays a well-structured summary of all threat relationships associated with the input file.
# - Each relationship category (e.g., malware families, campaigns) includes a list of entity IDs and types.
# - Indicates whether data was loaded from cache or freshly fetched from the API.
# - Provides clear error messages and retry suggestions if API calls fail.
#
# Usage:
# - Set your GTI_API_KEY and X_TOOL_HEADER in the configuration section.
# - Replace the example file hash in the `main()` function with your target file hash.
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
    "software_toolkits,campaigns,reports,vulnerabilities"
)

# Parameters for the API request, including relationships and their attributes
PARAMS = {
    "relationships": RELATIONSHIPS
}

def get_relationship_cache_file(file_hash: str) -> str:
    """
    Returns the file path for the relationship cache of a given file hash.

    Args:
        file_hash (str): The file hash.

    Returns:
        str: Cache file path.
    """
    return os.path.join(CACHE_DIR, f"file_{file_hash}_relationships_cache.json")


def get_cache_filename(file_hash: str, label: str) -> str:
    """
    Constructs the full path to a cache file for a given file hash and label.

    Args:
        file_hash (str): The hash of the file.
        label (str): The label for the specific type of cached data.

    Returns:
        str: Path to the cache file.
    """
    return os.path.join(CACHE_DIR, f"file_{file_hash}_{label}_cache.json")

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
            result['error'] = "Bad request - invalid file hash or parameters."
        elif response.status_code == 401:
            result['error'] = "Unauthorized - check your API key."
        elif response.status_code == 403:
            result['error'] = "Forbidden - insufficient permissions."
        elif response.status_code == 404:
            result['error'] = "File hash not found."
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

def get_file_relationships(file_hash: str) -> Dict:
    """
    Fetches relationship data from GTI for a given file hash, using local cache if available.

    Args:
        file_hash (str): The file hash to query.

    Returns:
        Dict: API response including relationship data.
    """
    cache_file = get_relationship_cache_file(file_hash)

    if os.path.exists(cache_file):
        print(f"\nFound cached relationship data for {file_hash}")
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
            return {'success': True, 'data': data}
        except (IOError, json.JSONDecodeError):
            print("Cache file could not be read. Will refetch from API...")

    print("\nNo cache file found. Fetching relationship data from API...")
    url = f"{BASE_URL}/files/{file_hash}"
    print(f"Fetching relationship data for file hash: {file_hash}")
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

def get_mitre_data(file_hash: str) -> Dict:
    """
    Fetches and caches MITRE ATT&CK technique data for the given file hash.

    Args:
        file_hash (str): The hash of the file.

    Returns:
        dict: Dictionary containing success status, MITRE data, error, and retry flag.
    """

    cache_file = get_cache_filename(file_hash, "mitre_data")

    if os.path.exists(cache_file):
        print(f"\nFound cached MITRE data for {file_hash}. Loading from file...")
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            return {'success': True, 'data': cached_data, 'error': None, 'status_code': 200, 'should_retry': False}
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error reading cache file for {file_hash}: {str(e)}. Proceeding with API call.")

    print(f"\nNo cache file found for {file_hash}. Fetching MITRE data from API...")
    url = f"{BASE_URL}/files/{file_hash}/behaviour_mitre_trees"
    api_response = make_api_request(url)

    if api_response['success']:
        os.makedirs(CACHE_DIR, exist_ok=True)
        try:
            with open(cache_file, 'w') as f:
                json.dump(api_response['data'], f, indent=2)
            print(f"Successfully saved MITRE data for {file_hash} to cache file: {cache_file}")
        except IOError as e:
            print(f"Warning: Failed to save MITRE data to cache file: {str(e)}")
    return api_response

def get_file_behaviours(file_hash: str) -> Dict:
    """
    Fetches sandbox behaviour data for the given file hash from the GTI API.

    This function first checks for cached sandbox behaviour data. If available and valid,
    it returns the cached data. Otherwise, it makes an API call to retrieve the data,
    caches the result, and returns it.

    Args:
        file_hash (str): The hash of the file to fetch sandbox behaviours for.

    Returns:
        Dict: A dictionary containing:
            - 'success' (bool): Whether the API call or cache read was successful.
            - 'data' (dict or None): The retrieved sandbox behaviour data.
            - 'error' (str or None): Any error message encountered.
            - 'status_code' (int): HTTP status code from the API or 200 if cache hit.
            - 'should_retry' (bool): Whether the operation should be retried.
    """

    cache_file = get_cache_filename(file_hash, "sandbox_behaviours")

    if os.path.exists(cache_file):
        print(f"\nFound cached sandbox behaviours data for {file_hash}. Loading from file...")
        try:
            with open(cache_file, 'r') as f:
                cached_data = json.load(f)
            return {'success': True, 'data': cached_data, 'error': None, 'status_code': 200, 'should_retry': False}
        except (IOError, json.JSONDecodeError) as e:
            print(f"Error reading cache file for {file_hash}: {str(e)}. Proceeding with API call.")

    print(f"\nNo cache file found for {file_hash}. Fetching sandbox behaviours data from API...")
    url = f"{BASE_URL}/files/{file_hash}/behaviours"
    api_response = make_api_request(url)

    if api_response['success']:
        os.makedirs(CACHE_DIR, exist_ok=True)
        try:
            with open(cache_file, 'w') as f:
                json.dump(api_response['data'], f, indent=2)
            print(f"Successfully saved sandbox behaviours data for {file_hash} to cache file: {cache_file}")
        except IOError as e:
            print(f"Warning: Failed to save sandbox behaviours data to cache file: {str(e)}")

    return api_response

def print_mitre_data(mitre_data: Dict, file_hash: str) -> bool:
    """
    Prints MITRE ATT&CK tactics and techniques data for a given file hash.

    This function processes and displays structured MITRE ATT&CK information from sandbox
    analysis. It includes tactics and techniques observed during execution across different
    sandbox environments. Handles errors gracefully and provides feedback for retry suggestions.

    Args:
        mitre_data (Dict): The MITRE data dictionary returned from the API or cache,
                        expected to follow the standard success/data/error structure.
        file_hash (str): The file hash used to identify the analysis subject.

    Returns:
        bool: True if MITRE data was successfully printed, False otherwise.
    """

    try:
        if not mitre_data.get('success'):
            print(f"Error fetching MITRE data for {file_hash}: {mitre_data.get('error', 'Unknown error')}")
            if mitre_data.get('should_retry'):
                print("Note: This request might succeed if retried later.")
            return False

        data = mitre_data.get('data', {}).get('data', {})

        if not data:
            print(f"No MITRE data found for file {file_hash}.")
            return False

        print(f"\n--- MITRE ATT&CK Data for File {file_hash} ---")

        for sandbox_name, sandbox_info in data.items():
            print(f"\nSandbox Name: {sandbox_name}")

            tactics = sandbox_info.get('tactics', [])
            if not tactics:
                print("  No tactics found for this sandbox.")
                continue

            for tactic in tactics:
                tactic_name = tactic.get('name', 'N/A')
                tactic_id = tactic.get('id', 'N/A')
                print(f"  - Tactic: {tactic_name} ({tactic_id})")

                techniques = tactic.get('techniques', [])
                if not techniques:
                    print("    No techniques found for this tactic.")
                    continue

                for technique in techniques:
                    technique_name = technique.get('name', 'N/A')
                    technique_id = technique.get('id', 'N/A')
                    print(f"    - Technique: {technique_name} ({technique_id})")

        return True

    except Exception as e:
        print(f"Error processing MITRE data: {str(e)}")
        return False

def print_sandbox_behaviours(behaviours_result: Dict,file_hash: str) -> None:
    """
    Prints sandbox behavior analysis results for a given file hash.

    This function displays the sandbox behaviors observed during dynamic analysis of a file,
    including sandbox names and associated behavior IDs. It handles missing or error responses
    gracefully and formats the output for readability.

    Args:
        behaviours_result (Dict): The result dictionary containing sandbox behavior data, 
                                expected to follow the success/data/error format.
        file_hash (str): The file hash used to identify the scanned file.

    Returns:
        None
    """

    print(f"\n--- Sandbox Behavior Analysis for File {file_hash} ---")

    if not behaviours_result['success']:
        print(f"Error retrieving sandbox behaviors: {behaviours_result['error']}")
        return

    behaviours_data = behaviours_result['data'].get("data", [])
    if not behaviours_data:
        print("No sandbox behavior data found.")
        return

    for behaviour in behaviours_data:
        attrs = behaviour.get('attributes', {})
        sandbox_name = attrs.get('sandbox_name', 'N/A')
        behaviour_id = behaviour.get('id', 'N/A')

        print(f"\nSandbox Name: {sandbox_name}")
        print(f"Behavior ID: {behaviour_id}")
        print(f"Command executions observed during the analysis of the file in the sandbox {sandbox_name}:")
        command_executions = attrs.get('command_executions', [])
        if not command_executions:
            print("  No command executions found.")
            continue
        for command in command_executions:
            print(f"  - Command: {command}")
        print("---")

def print_relationships(response: Dict, file_hash: str):
    """
    Nicely prints the relationship data from the API response.

    Args:
        response (Dict): The GTI API response containing relationship data.
        file_hash (str): The file hash analyzed.
    """
    if not response.get('success'):
        print(f"{response.get('error', 'Unknown error')}")
        return

    data = response['data'].get('data', {})
    relationships = data.get('relationships', {})

    if not relationships:
        print(f"No relationships found for file hash: {file_hash}")
        return

    print(f"\n--- Relationship Summary for File Hash: {file_hash} ---")
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
    Main entry point for the file hash analysis script.

    This function orchestrates the workflow of querying and displaying
    various threat intelligence data for a specified file hash. It performs:
      - Relationship analysis (collections, malware families, threat actors, etc.)
      - MITRE ATT&CK framework analysis
      - Sandbox behavior analysis

    The function also handles retries for failed API calls.

    Modify the `file_hash` variable to analyze a different file.

    Returns:
        None
    """

    file_hash = "001a2541de77dc468f7986948da56b03dad2f57c59b77142451bd4c9bef8f8d0"  # Replace with your target file hash
    print(f"Analyzing file hash: {file_hash}")

    print(f"\nStartinng Relationship Analysis for: {file_hash}")
    file_relationships = get_file_relationships(file_hash)
    if not file_relationships['success'] and file_relationships.get('should_retry'):
        print("\nRetrying failed request...")
        file_relationships = get_file_relationships(file_hash)
    print_relationships(file_relationships, file_hash)
    print("======" * 20)

    print(f"\nStartinng MITRE Analysis for: {file_hash}")
    mitre_result = get_mitre_data(file_hash)
    if not mitre_result['success'] and mitre_result.get('should_retry'):
        print("\nRetrying failed request...")
        mitre_result = get_mitre_data(file_hash)
    print_mitre_data(mitre_result, file_hash)
    print("======" * 20)

    print(f"\nStartinng Sandbox Behavior Analysis for: {file_hash}")
    behaviours_result = get_file_behaviours(file_hash)
    if not behaviours_result['success'] and behaviours_result.get('should_retry'):
        print("\nRetrying failed request...")
        behaviours_result = get_file_behaviours(file_hash)
    print_sandbox_behaviours(behaviours_result,file_hash)
    print("======" * 20)

    print(f"\nAnalysis completed for: {file_hash}")

if __name__ == "__main__":
    main()
