import pytest
from unittest.mock import patch, MagicMock
import json
import requests
from examples.threat_list_and_ioc_stream_ingestion.ingest_threat_list import (
    make_api_request,
    get_threat_list,
    get_threat_list_hourly,
    print_threat_list,
    print_hourly_threat_list,
    main,
    BASE_URL,
    GTI_API_KEY,
    X_TOOL_HEADER,
)
from testcases.constants import THREAT_LIST_API_RESPONSE


@pytest.fixture
def mock_requests():
    with patch("requests.get") as mock_request:
        yield mock_request


@pytest.fixture
def mock_response():
    mock = MagicMock()
    return mock


def test_make_api_request_success(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = THREAT_LIST_API_RESPONSE
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/ransomware/latest")

    assert result["success"] is True
    assert result["data"] == THREAT_LIST_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        f"{BASE_URL}/threat_lists/ransomware/latest",
        headers={"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
        timeout=60,
    )


def test_make_api_request_400_bad_request(mock_requests):
    mock_response = MagicMock(status_code=400)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/invalid/latest")

    assert result["success"] is False
    assert result["error"] == "Bad request - invalid parameters"
    assert result["status_code"] == 400
    assert result["should_retry"] is False


def test_make_api_request_401_unauthorized(mock_requests):
    mock_response = MagicMock(status_code=401)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/ransomware/latest")

    assert result["success"] is False
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["status_code"] == 401
    assert result["should_retry"] is False


def test_make_api_request_403_forbidden(mock_requests):
    mock_response = MagicMock(status_code=403)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/ransomware/latest")

    assert result["success"] is False
    assert result["error"] == "Forbidden - insufficient permissions"
    assert result["status_code"] == 403
    assert result["should_retry"] is False


def test_make_api_request_404_not_found(mock_requests):
    mock_response = MagicMock(status_code=404)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/ransomware/latest")

    assert result["success"] is False
    assert result["error"] == "Threat list not found or invalid timestamp"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_make_api_request_429_rate_limit(mock_requests):
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/ransomware/latest")

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_make_api_request_500_server_error(mock_requests):
    mock_response = MagicMock(status_code=500)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/ransomware/latest")

    assert result["success"] is False
    assert result["error"] == "Server error (HTTP 500)"
    assert result["status_code"] == 500
    assert result["should_retry"] is True


def test_make_api_request_timeout(mock_requests):
    mock_requests.side_effect = requests.exceptions.Timeout

    result = make_api_request("threat_lists/ransomware/latest")

    assert result["success"] is False
    assert result["error"] == "Request timed out"
    assert result["should_retry"] is True


def test_make_api_request_connection_error(mock_requests):
    mock_requests.side_effect = requests.exceptions.ConnectionError

    result = make_api_request("threat_lists/ransomware/latest")

    assert result["success"] is False
    assert result["error"] == "Connection error - check your network"
    assert result["should_retry"] is True


def test_make_api_request_json_decode_error(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/ransomware/latest")

    assert result["success"] is False
    assert result["error"] == "Failed to parse JSON response: Invalid JSON"
    assert result["should_retry"] is False


def test_make_api_request_unexpected_error(mock_requests):
    mock_requests.side_effect = requests.exceptions.RequestException("Unexpected error")

    result = make_api_request("threat_lists/ransomware/latest")

    assert result["success"] is False
    assert result["error"] == "Request failed: Unexpected error"
    assert result["should_retry"] is False


def test_get_threat_list_success(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = THREAT_LIST_API_RESPONSE
    mock_requests.return_value = mock_response

    result = get_threat_list("ransomware")

    assert result["success"] is True
    assert result["data"] == THREAT_LIST_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        f"{BASE_URL}/threat_lists/ransomware/latest",
        headers={"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
        timeout=60,
    )


def test_get_threat_list_rate_limit(mock_requests):
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = get_threat_list("ransomware")

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_get_threat_list_not_found(mock_requests):
    mock_response = MagicMock(status_code=404)
    mock_requests.return_value = mock_response

    result = get_threat_list("invalid")

    assert result["success"] is False
    assert result["error"] == "Threat list not found or invalid timestamp"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_get_threat_list_hourly_success(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = THREAT_LIST_API_RESPONSE
    mock_requests.return_value = mock_response

    result = get_threat_list_hourly("cryptominer", "2025021913")

    assert result["success"] is True
    assert result["data"] == THREAT_LIST_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        f"{BASE_URL}/threat_lists/cryptominer/2025021913",
        headers={"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
        timeout=60,
    )


def test_get_threat_list_hourly_rate_limit(mock_requests):
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = get_threat_list_hourly("cryptominer", "2025021913")

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_get_threat_list_hourly_not_found(mock_requests):
    mock_response = MagicMock(status_code=404)
    mock_requests.return_value = mock_response

    result = get_threat_list_hourly("cryptominer", "2025021913")

    assert result["success"] is False
    assert result["error"] == "Threat list not found or invalid timestamp"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_print_threat_list_success(capsys):
    response = {
        "success": True,
        "data": THREAT_LIST_API_RESPONSE,
        "error": None,
        "status_code": 200,
        "should_retry": False,
    }

    result = print_threat_list(response, "ransomware", limit=2)

    captured = capsys.readouterr()
    assert result is True
    assert "=== Latest Ransomware Threat List ===" in captured.out
    assert "Total entries: 3" in captured.out
    assert "Displaying (first 2) entries:" in captured.out
    assert json.dumps(THREAT_LIST_API_RESPONSE["iocs"][:2], indent=2) in captured.out


def test_print_threat_list_empty_iocs(capsys):
    response = {
        "success": True,
        "data": {"iocs": []},
        "error": None,
        "status_code": 200,
        "should_retry": False,
    }

    result = print_threat_list(response, "ransomware")

    captured = capsys.readouterr()
    assert result is True
    assert "No IOCs found in the 'ransomware' threat list." in captured.out


def test_print_threat_list_failure(capsys):
    response = {
        "success": False,
        "data": None,
        "error": "Rate limit exceeded",
        "status_code": 429,
        "should_retry": True,
    }

    result = print_threat_list(response, "ransomware")

    captured = capsys.readouterr()
    assert result is False
    assert (
        "Error fetching 'ransomware' threat list: Rate limit exceeded" in captured.out
    )
    assert "Note: This request might succeed if retried later." in captured.out


def test_print_hourly_threat_list_success(capsys):
    response = {
        "success": True,
        "data": THREAT_LIST_API_RESPONSE,
        "error": None,
        "status_code": 200,
        "should_retry": False,
    }

    result = print_hourly_threat_list(response, "cryptominer", "2025021913", limit=2)

    captured = capsys.readouterr()
    assert result is True
    assert "=== Cryptominer Threat List for Hour: 2025021913 ===" in captured.out
    assert "Total entries: 3" in captured.out
    assert "Displaying (first 2) entries:" in captured.out
    assert json.dumps(THREAT_LIST_API_RESPONSE["iocs"][:2], indent=2) in captured.out


def test_print_hourly_threat_list_empty_iocs(capsys):
    response = {
        "success": True,
        "data": {"iocs": []},
        "error": None,
        "status_code": 200,
        "should_retry": False,
    }

    result = print_hourly_threat_list(response, "cryptominer", "2025021913")

    captured = capsys.readouterr()
    assert result is True
    assert (
        "No IOCs found in the 'cryptominer' threat list for timestamp 2025021913."
        in captured.out
    )


def test_print_hourly_threat_list_failure(capsys):
    response = {
        "success": False,
        "data": None,
        "error": "Rate limit exceeded",
        "status_code": 429,
        "should_retry": True,
    }

    result = print_hourly_threat_list(response, "cryptominer", "2025021913")

    captured = capsys.readouterr()
    assert result is False
    assert (
        "Error fetching 'cryptominer' threat list for timestamp 2025021913: Rate limit exceeded"
        in captured.out
    )
    assert "Note: This request might succeed if retried later." in captured.out


def test_main_success(mock_requests, capsys):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = THREAT_LIST_API_RESPONSE
    mock_requests.side_effect = [mock_response, mock_response]

    main()

    captured = capsys.readouterr()
    assert "Fetching latest 'ransomware' threat list..." in captured.out
    assert "Fetching 'cryptominer' threat list for hour '2025021913'..." in captured.out
    assert "=== Latest Ransomware Threat List ===" in captured.out
    assert "=== Cryptominer Threat List for Hour: 2025021913 ===" in captured.out
    assert "Total entries: 3" in captured.out
    assert mock_requests.call_count == 2
    assert (
        mock_requests.call_args_list[0][0][0]
        == f"{BASE_URL}/threat_lists/ransomware/latest"
    )
    assert (
        mock_requests.call_args_list[1][0][0]
        == f"{BASE_URL}/threat_lists/cryptominer/2025021913"
    )


def test_main_retry_on_failure(mock_requests, capsys):
    mock_response_fail = MagicMock(status_code=429)
    mock_response_success = MagicMock(status_code=200)
    mock_response_success.json.return_value = THREAT_LIST_API_RESPONSE
    mock_requests.side_effect = [
        mock_response_fail,
        mock_response_success,
        mock_response_success,
    ]

    main()

    captured = capsys.readouterr()
    assert "Retrying failed request..." in captured.out
    assert "=== Latest Ransomware Threat List ===" in captured.out
    assert "=== Cryptominer Threat List for Hour: 2025021913 ===" in captured.out
    assert "Total entries: 3" in captured.out
    assert mock_requests.call_count == 3
    assert (
        mock_requests.call_args_list[0][0][0]
        == f"{BASE_URL}/threat_lists/ransomware/latest"
    )
    assert (
        mock_requests.call_args_list[1][0][0]
        == f"{BASE_URL}/threat_lists/ransomware/latest"
    )
    assert (
        mock_requests.call_args_list[2][0][0]
        == f"{BASE_URL}/threat_lists/cryptominer/2025021913"
    )


def test_main_both_requests_fail(mock_requests, capsys):
    mock_response = MagicMock(status_code=429)
    mock_requests.side_effect = [
        mock_response,
        mock_response,
        mock_response,
        mock_response,
    ]

    main()

    captured = capsys.readouterr()
    assert "Retrying failed request..." in captured.out
    assert (
        "Error fetching 'ransomware' threat list: Rate limit exceeded" in captured.out
    )
    assert (
        "Error fetching 'cryptominer' threat list for timestamp 2025021913: Rate limit exceeded"
        in captured.out
    )
    assert "Note: This request might succeed if retried later." in captured.out
    assert mock_requests.call_count == 4
    assert (
        mock_requests.call_args_list[0][0][0]
        == f"{BASE_URL}/threat_lists/ransomware/latest"
    )
    assert (
        mock_requests.call_args_list[1][0][0]
        == f"{BASE_URL}/threat_lists/ransomware/latest"
    )
    assert (
        mock_requests.call_args_list[2][0][0]
        == f"{BASE_URL}/threat_lists/cryptominer/2025021913"
    )
    assert (
        mock_requests.call_args_list[3][0][0]
        == f"{BASE_URL}/threat_lists/cryptominer/2025021913"
    )
