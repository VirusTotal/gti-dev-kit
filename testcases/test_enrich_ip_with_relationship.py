import pytest
import os
import json
import requests
from unittest.mock import patch, mock_open, MagicMock
from examples.automatic_and_manual_enrichment.enrich_ip_with_relationship import (
    get_relationship_cache_file,
    make_api_request,
    get_ip_relationships,
    print_relationships,
    CACHE_DIR,
    BASE_URL,
    PARAMS,
)

from testcases.constants import IP_ADDRESS, ENRICH_IP_RELATIONSHIP_API_RESPONSE

MOCK_CACHE_FILE = os.path.join(CACHE_DIR, f"ip_{IP_ADDRESS}_relationships_cache.json")


@pytest.fixture
def mock_requests_get():
    with patch("requests.get") as mock_get:
        yield mock_get


@pytest.fixture
def mock_os_path_exists():
    with patch("os.path.exists") as mock_exists:
        yield mock_exists


@pytest.fixture
def mock_open_file():
    with patch("builtins.open", mock_open()) as mock_file:
        yield mock_file


@pytest.fixture
def mock_os_makedirs():
    with patch("os.makedirs") as mock_mkdir:
        yield mock_mkdir


@pytest.fixture
def mock_json_dump():
    with patch("json.dump") as mock_dump:
        yield mock_dump


def test_get_relationship_cache_file():
    """Test cache filename generation for relationships."""
    expected = os.path.join(CACHE_DIR, f"ip_{IP_ADDRESS}_relationships_cache.json")
    result = get_relationship_cache_file(IP_ADDRESS)
    assert result == expected, f"Expected cache filename {expected}, got {result}"


def test_make_api_request_success(mock_requests_get):
    """Test successful API request."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_IP_RELATIONSHIP_API_RESPONSE
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ip_addresses/{IP_ADDRESS}", params=PARAMS)

    assert result["success"] is True
    assert result["data"] == ENRICH_IP_RELATIONSHIP_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests_get.assert_called_once_with(
        f"{BASE_URL}/ip_addresses/{IP_ADDRESS}",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        params=PARAMS,
        timeout=60,
    )


def test_make_api_request_400_bad_request(mock_requests_get):
    """Test API request with 400 Bad Request."""
    mock_response = MagicMock(status_code=400)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ip_addresses/{IP_ADDRESS}", params=PARAMS)

    assert result["success"] is False
    assert result["error"] == "Bad request - invalid IP address or parameters."
    assert result["status_code"] == 400
    assert result["should_retry"] is False


def test_make_api_request_401_unauthorized(mock_requests_get):
    """Test API request with 401 Unauthorized."""
    mock_response = MagicMock(status_code=401)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ip_addresses/{IP_ADDRESS}", params=PARAMS)

    assert result["success"] is False
    assert result["error"] == "Unauthorized - check your API key."
    assert result["status_code"] == 401
    assert result["should_retry"] is False


def test_make_api_request_403_forbidden(mock_requests_get):
    """Test API request with 403 Forbidden."""
    mock_response = MagicMock(status_code=403)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ip_addresses/{IP_ADDRESS}", params=PARAMS)

    assert result["success"] is False
    assert result["error"] == "Forbidden - insufficient permissions."
    assert result["status_code"] == 403
    assert result["should_retry"] is False


def test_make_api_request_404_not_found(mock_requests_get):
    """Test API request with 404 Not Found."""
    mock_response = MagicMock(status_code=404)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ip_addresses/{IP_ADDRESS}", params=PARAMS)

    assert result["success"] is False
    assert result["error"] == "IP address not found."
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_make_api_request_429_rate_limit(mock_requests_get):
    """Test API request with 429 Rate Limit Exceeded."""
    mock_response = MagicMock(status_code=429)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ip_addresses/{IP_ADDRESS}", params=PARAMS)

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded."
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_make_api_request_500_server_error(mock_requests_get):
    """Test API request with 500 Server Error."""
    mock_response = MagicMock(status_code=500)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ip_addresses/{IP_ADDRESS}", params=PARAMS)

    assert result["success"] is False
    assert result["error"] == "Server error 500."
    assert result["status_code"] == 500
    assert result["should_retry"] is True


def test_make_api_request_timeout(mock_requests_get):
    """Test API request with timeout."""
    mock_requests_get.side_effect = requests.exceptions.Timeout

    result = make_api_request(f"{BASE_URL}/ip_addresses/{IP_ADDRESS}", params=PARAMS)

    assert result["success"] is False
    assert result["error"] == "Request timed out."
    assert result["should_retry"] is True


def test_make_api_request_connection_error(mock_requests_get):
    """Test API request with connection error."""
    mock_requests_get.side_effect = requests.exceptions.ConnectionError

    result = make_api_request(f"{BASE_URL}/ip_addresses/{IP_ADDRESS}", params=PARAMS)

    assert result["success"] is False
    assert result["error"] == "Connection error. Check your internet connection."
    assert result["should_retry"] is True


def test_make_api_request_unexpected_error(mock_requests_get):
    """Test API request with unexpected error."""
    mock_requests_get.side_effect = requests.exceptions.RequestException(
        "Unexpected error"
    )

    result = make_api_request(f"{BASE_URL}/ip_addresses/{IP_ADDRESS}", params=PARAMS)

    assert result["success"] is False
    assert result["error"] == "Unexpected error: Unexpected error"
    assert result["should_retry"] is False


def test_get_ip_relationships_from_cache(mock_os_path_exists, mock_open_file):
    """Test fetching relationship data from cache."""
    mock_os_path_exists.return_value = True
    mock_open_file().read.return_value = json.dumps(ENRICH_IP_RELATIONSHIP_API_RESPONSE)

    result = get_ip_relationships(IP_ADDRESS)

    assert result["success"] is True
    assert result["data"] == ENRICH_IP_RELATIONSHIP_API_RESPONSE
    mock_open_file.assert_called_with(MOCK_CACHE_FILE, "r")


def test_get_ip_relationships_cache_io_error(
    mock_os_path_exists, mock_open_file, mock_requests_get
):
    """Test cache read error, falling back to API."""
    mock_os_path_exists.return_value = True
    mock_open_file.side_effect = IOError("Cannot read file")
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_IP_RELATIONSHIP_API_RESPONSE
    mock_requests_get.return_value = mock_response

    result = get_ip_relationships(IP_ADDRESS)

    assert result["success"] is True
    assert result["data"] == ENRICH_IP_RELATIONSHIP_API_RESPONSE
    mock_requests_get.assert_called_once()


def test_get_ip_relationships_no_cache_api_success(
    mock_os_path_exists,
    mock_requests_get,
    mock_open_file,
    mock_os_makedirs,
    mock_json_dump,
):
    """Test fetching relationship data from API with successful cache save."""
    mock_os_path_exists.return_value = False
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_IP_RELATIONSHIP_API_RESPONSE
    mock_requests_get.return_value = mock_response

    result = get_ip_relationships(IP_ADDRESS)

    assert result["success"] is True
    assert result["data"] == ENRICH_IP_RELATIONSHIP_API_RESPONSE
    mock_os_makedirs.assert_called_with(CACHE_DIR, exist_ok=True)
    mock_open_file.assert_called_with(MOCK_CACHE_FILE, "w")
    mock_json_dump.assert_called_once_with(
        ENRICH_IP_RELATIONSHIP_API_RESPONSE, mock_open_file(), indent=2
    )


def test_get_ip_relationships_no_cache_cache_write_error(
    mock_os_path_exists, mock_requests_get, mock_open_file, mock_os_makedirs
):
    """Test API success but cache write failure."""
    mock_os_path_exists.return_value = False
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_IP_RELATIONSHIP_API_RESPONSE
    mock_requests_get.return_value = mock_response
    mock_open_file.side_effect = IOError("Cannot write file")

    result = get_ip_relationships(IP_ADDRESS)

    assert result["success"] is True
    assert result["data"] == ENRICH_IP_RELATIONSHIP_API_RESPONSE
    mock_os_makedirs.assert_called_with(CACHE_DIR, exist_ok=True)
    mock_open_file.assert_called_with(MOCK_CACHE_FILE, "w")


def test_print_relationships_success(capsys):
    """Test printing a successful relationship response."""
    print_relationships(
        {"success": True, "data": ENRICH_IP_RELATIONSHIP_API_RESPONSE}, IP_ADDRESS
    )
    captured = capsys.readouterr()

    assert f"Relationship Summary for IP: {IP_ADDRESS}" in captured.out
    assert "> Malware Families:" in captured.out
    assert "- ID: analysis_virustotal_cape_dcrat | Type: collection" in captured.out
    assert "> Related Threat Actors:" in captured.out
    assert "- No related entities found." in captured.out
    assert "> Resolutions:" in captured.out
    assert f"- ID: {IP_ADDRESS}sanam.ie | Type: resolution" in captured.out
    assert "> Reports:" in captured.out
    assert "- ID: report--19-00000879 | Type: collection" in captured.out


def test_print_relationships_failed_request(capsys):
    """Test printing a failed relationship response."""
    response = {"success": False, "error": "API error"}
    print_relationships(response, IP_ADDRESS)
    captured = capsys.readouterr()

    assert "API error" in captured.out


def test_print_relationships_no_relationships(capsys):
    """Test printing a response with no relationships."""
    response = {"success": True, "data": {"data": {}}}
    print_relationships(response, IP_ADDRESS)
    captured = capsys.readouterr()

    assert f"No relationships found for IP: {IP_ADDRESS}" in captured.out


def test_print_relationships_empty_relationships(capsys):
    """Test printing a response with empty relationships."""
    response = {"success": True, "data": {"data": {"relationships": {}}}}
    print_relationships(response, IP_ADDRESS)
    captured = capsys.readouterr()

    assert f"No relationships found for IP: {IP_ADDRESS}" in captured.out


def test_main_retry_logic(mock_os_path_exists, mock_requests_get, capsys):
    """Test main function retry logic on failed request."""
    mock_os_path_exists.return_value = False
    mock_response_fail = MagicMock(status_code=429)
    mock_response_success = MagicMock(status_code=200)
    mock_response_success.json.return_value = ENRICH_IP_RELATIONSHIP_API_RESPONSE
    mock_requests_get.side_effect = [mock_response_fail, mock_response_success]

    with patch(
        "examples.automatic_and_manual_enrichment.enrich_ip_with_relationship.get_ip_relationships"
    ) as mock_get_ip_relationships:
        mock_get_ip_relationships.side_effect = [
            {"success": False, "error": "Rate limit exceeded.", "should_retry": True},
            {"success": True, "data": ENRICH_IP_RELATIONSHIP_API_RESPONSE},
        ]
        from examples.automatic_and_manual_enrichment.enrich_ip_with_relationship import (
            main,
        )

        main()

    captured = capsys.readouterr()
    assert "Retrying failed request..." in captured.out
    assert f"Relationship Summary for IP: {IP_ADDRESS}" in captured.out
