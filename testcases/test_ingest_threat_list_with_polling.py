import pytest
from unittest.mock import patch, MagicMock
import json
import requests
from datetime import datetime, timezone
from examples.threat_list_and_ioc_stream_ingestion.ingest_threat_list_with_polling import (
    make_api_request,
    get_threat_list_hourly,
    print_hourly_threat_list,
    poll_hourly_threat_lists,
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
def mock_time_sleep():
    with patch("time.sleep") as mock_sleep:
        yield mock_sleep


@pytest.fixture
def mock_datetime(monkeypatch):
    class MockDatetime:
        @staticmethod
        def now(tz=None):
            return datetime(2025, 8, 14, 7, 52, 0, tzinfo=timezone.utc)

    monkeypatch.setattr(
        "examples.threat_list_and_ioc_stream_ingestion.ingest_threat_list_with_polling.datetime",
        MockDatetime,
    )
    return MockDatetime


def test_make_api_request_success(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = THREAT_LIST_API_RESPONSE
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/cryptominer/2025081407")

    assert result["success"] is True
    assert result["data"] == THREAT_LIST_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        f"{BASE_URL}/threat_lists/cryptominer/2025081407",
        headers={"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
        timeout=60,
    )


def test_make_api_request_400_bad_request(mock_requests):
    mock_response = MagicMock(status_code=400)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/invalid/2025081407")

    assert result["success"] is False
    assert result["error"] == "Bad request - invalid parameters"
    assert result["status_code"] == 400
    assert result["should_retry"] is False


def test_make_api_request_401_unauthorized(mock_requests):
    mock_response = MagicMock(status_code=401)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/cryptominer/2025081407")

    assert result["success"] is False
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["status_code"] == 401
    assert result["should_retry"] is False


def test_make_api_request_403_forbidden(mock_requests):
    mock_response = MagicMock(status_code=403)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/cryptominer/2025081407")

    assert result["success"] is False
    assert result["error"] == "Forbidden - insufficient permissions"
    assert result["status_code"] == 403
    assert result["should_retry"] is False


def test_make_api_request_404_not_found(mock_requests):
    mock_response = MagicMock(status_code=404)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/cryptominer/2025081407")

    assert result["success"] is False
    assert result["error"] == "Threat list not found or invalid timestamp"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_make_api_request_429_rate_limit(mock_requests):
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/cryptominer/2025081407")

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_make_api_request_500_server_error(mock_requests):
    mock_response = MagicMock(status_code=500)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/cryptominer/2025081407")

    assert result["success"] is False
    assert result["error"] == "Server error (HTTP 500)"
    assert result["status_code"] == 500
    assert result["should_retry"] is True


def test_make_api_request_unexpected_http_status(mock_requests):
    """Test API request with 500 Server Error."""
    mock_response = MagicMock(status_code=900)
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/cryptominer/2025081407")

    assert result["success"] is False
    assert result["error"] == "Unexpected HTTP status: 900"
    assert result["status_code"] == 900
    assert result["should_retry"] is False


def test_make_api_unexpected_error(mock_requests):
    """Test API request with connection error."""
    mock_requests.side_effect = Exception("Unexpected error")

    result = make_api_request("threat_lists/cryptominer/2025081407")

    assert result["success"] is False
    assert result["error"] == "Unexpected error: Unexpected error"
    assert result["should_retry"] is False


def test_make_api_request_timeout(mock_requests):
    mock_requests.side_effect = requests.exceptions.Timeout

    result = make_api_request("threat_lists/cryptominer/2025081407")

    assert result["success"] is False
    assert result["error"] == "Request timed out"
    assert result["should_retry"] is True


def test_make_api_request_connection_error(mock_requests):
    mock_requests.side_effect = requests.exceptions.ConnectionError

    result = make_api_request("threat_lists/cryptominer/2025081407")

    assert result["success"] is False
    assert result["error"] == "Connection error - check your network"
    assert result["should_retry"] is True


def test_make_api_request_json_decode_error(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_requests.return_value = mock_response

    result = make_api_request("threat_lists/cryptominer/2025081407")

    assert result["success"] is False
    assert result["error"] == "Failed to parse JSON response: Invalid JSON"
    assert result["should_retry"] is False


def test_make_api_request_unexpected_error(mock_requests):
    mock_requests.side_effect = requests.exceptions.RequestException("Unexpected error")

    result = make_api_request("threat_lists/cryptominer/2025081407")

    assert result["success"] is False
    assert result["error"] == "Request failed: Unexpected error"
    assert result["should_retry"] is False


def test_get_threat_list_hourly_success(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = THREAT_LIST_API_RESPONSE
    mock_requests.return_value = mock_response

    result = get_threat_list_hourly("cryptominer", "2025081407")

    assert result["success"] is True
    assert result["data"] == THREAT_LIST_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        f"{BASE_URL}/threat_lists/cryptominer/2025081407",
        headers={"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
        timeout=60,
    )


def test_get_threat_list_hourly_rate_limit(mock_requests):
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = get_threat_list_hourly("cryptominer", "2025081407")

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_get_threat_list_hourly_not_found(mock_requests):
    mock_response = MagicMock(status_code=404)
    mock_requests.return_value = mock_response

    result = get_threat_list_hourly("cryptominer", "2025081407")

    assert result["success"] is False
    assert result["error"] == "Threat list not found or invalid timestamp"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_print_hourly_threat_list_success(capsys):
    response = {
        "success": True,
        "data": THREAT_LIST_API_RESPONSE,
        "error": None,
        "status_code": 200,
        "should_retry": False,
    }

    result = print_hourly_threat_list(response, "cryptominer", "2025081407", limit=2)

    captured = capsys.readouterr()
    assert result is True
    assert "=== Cryptominer Threat List for Hour: 2025081407 ===" in captured.out
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

    result = print_hourly_threat_list(response, "cryptominer", "2025081407")

    captured = capsys.readouterr()
    assert result is True
    assert (
        "No IOCs found in the 'cryptominer' threat list for timestamp 2025081407."
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

    result = print_hourly_threat_list(response, "cryptominer", "2025081407")

    captured = capsys.readouterr()
    assert result is False
    assert (
        "Error fetching 'cryptominer' threat list for timestamp 2025081407: Rate limit exceeded"
        in captured.out
    )
    assert "Note: This request might succeed if retried later." in captured.out


def test_print_hourly_threat_list_invalid_data(capsys):
    response = {
        "success": True,
        "data": {},
        "error": None,
        "status_code": 200,
        "should_retry": False,
    }

    result = print_hourly_threat_list(response, "cryptominer", "2025081407")

    captured = capsys.readouterr()
    assert result is True
    assert (
        "No IOCs found in the 'cryptominer' threat list for timestamp 2025081407."
        in captured.out
    )


def test_poll_hourly_threat_lists_success(
    mock_requests, mock_time_sleep, mock_datetime, capsys
):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = THREAT_LIST_API_RESPONSE
    mock_requests.side_effect = [mock_response] * 5

    poll_hourly_threat_lists("cryptominer", polls=5, interval=5)

    captured = capsys.readouterr()
    assert "Starting polling at: 2025-08-14 02:52:00 UTC" in captured.out
    assert "Polling 'cryptominer' threat list for 5 hours..." in captured.out
    for i in range(5):
        timestamp = f"20250814{2+i:02d}"
        assert f"=== Poll {i+1}/5 | Timestamp: {timestamp} ===" in captured.out
        assert f"=== Cryptominer Threat List for Hour: {timestamp} ===" in captured.out
        assert "Total entries: 3" in captured.out
    assert mock_requests.call_count == 5
    assert mock_time_sleep.call_count == 4
    assert mock_time_sleep.call_args_list == [((5,),)] * 4
    expected_urls = [
        f"{BASE_URL}/threat_lists/cryptominer/20250814{2+i:02d}" for i in range(5)
    ]
    actual_urls = [call[0][0] for call in mock_requests.call_args_list]
    assert actual_urls == expected_urls


def test_poll_hourly_threat_lists_retry_on_failure(
    mock_requests, mock_time_sleep, mock_datetime, capsys
):
    mock_response_fail = MagicMock(status_code=429)
    mock_response_success = MagicMock(status_code=200)
    mock_response_success.json.return_value = THREAT_LIST_API_RESPONSE
    mock_requests.side_effect = [mock_response_fail, mock_response_success] * 5

    poll_hourly_threat_lists("cryptominer", polls=5, interval=5)

    captured = capsys.readouterr()
    assert "Starting polling at: 2025-08-14 02:52:00 UTC" in captured.out
    assert "Polling 'cryptominer' threat list for 5 hours..." in captured.out
    for i in range(5):
        timestamp = f"20250814{2+i:02d}"
        assert f"=== Poll {i+1}/5 | Timestamp: {timestamp} ===" in captured.out
        assert f"Request failed. Retrying..." in captured.out
        assert f"=== Cryptominer Threat List for Hour: {timestamp} ===" in captured.out
        assert "Total entries: 3" in captured.out
    assert mock_requests.call_count == 10
    assert mock_time_sleep.call_count == 4
    assert mock_time_sleep.call_args_list == [((5,),)] * 4
    expected_urls = [
        f"{BASE_URL}/threat_lists/cryptominer/20250814{2+i:02d}"
        for i in range(5)
        for _ in range(2)
    ]
    actual_urls = [call[0][0] for call in mock_requests.call_args_list]
    assert actual_urls == expected_urls


def test_poll_hourly_threat_lists_all_failures(
    mock_requests, mock_time_sleep, mock_datetime, capsys
):
    mock_response = MagicMock(status_code=429)
    mock_requests.side_effect = [mock_response] * 10

    poll_hourly_threat_lists("cryptominer", polls=5, interval=5)

    captured = capsys.readouterr()
    assert "Starting polling at: 2025-08-14 02:52:00 UTC" in captured.out
    assert "Polling 'cryptominer' threat list for 5 hours..." in captured.out
    for i in range(5):
        timestamp = f"20250814{2+i:02d}"
        assert f"=== Poll {i+1}/5 | Timestamp: {timestamp} ===" in captured.out
        assert f"Request failed. Retrying..." in captured.out
        assert (
            f"Error fetching 'cryptominer' threat list for timestamp {timestamp}: Rate limit exceeded"
            in captured.out
        )
        assert "Note: This request might succeed if retried later." in captured.out
    assert mock_requests.call_count == 10
    assert mock_time_sleep.call_count == 4
    assert mock_time_sleep.call_args_list == [((5,),)] * 4
    expected_urls = [
        f"{BASE_URL}/threat_lists/cryptominer/20250814{2+i:02d}"
        for i in range(5)
        for _ in range(2)
    ]
    actual_urls = [call[0][0] for call in mock_requests.call_args_list]
    assert actual_urls == expected_urls


def test_main_success(mock_requests, mock_time_sleep, mock_datetime, capsys):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = THREAT_LIST_API_RESPONSE
    mock_requests.side_effect = [mock_response] * 5

    main()

    captured = capsys.readouterr()
    assert "------ Threat List Hourly Polling -----" in captured.out
    assert "Starting polling at: 2025-08-14 02:52:00 UTC" in captured.out
    assert "Polling 'cryptominer' threat list for 5 hours..." in captured.out
    for i in range(5):
        timestamp = f"20250814{2+i:02d}"
        assert f"=== Poll {i+1}/5 | Timestamp: {timestamp} ===" in captured.out
        assert f"=== Cryptominer Threat List for Hour: {timestamp} ===" in captured.out
        assert "Total entries: 3" in captured.out
    assert mock_requests.call_count == 5
    assert mock_time_sleep.call_count == 4
    assert mock_time_sleep.call_args_list == [((5,),)] * 4
    expected_urls = [
        f"{BASE_URL}/threat_lists/cryptominer/20250814{2+i:02d}" for i in range(5)
    ]
    actual_urls = [call[0][0] for call in mock_requests.call_args_list]
    assert actual_urls == expected_urls


def test_main_retry_on_failure(mock_requests, mock_time_sleep, mock_datetime, capsys):
    mock_response_fail = MagicMock(status_code=429)
    mock_response_success = MagicMock(status_code=200)
    mock_response_success.json.return_value = THREAT_LIST_API_RESPONSE
    mock_requests.side_effect = [mock_response_fail, mock_response_success] * 5

    main()

    captured = capsys.readouterr()
    assert "------ Threat List Hourly Polling -----" in captured.out
    assert "Starting polling at: 2025-08-14 02:52:00 UTC" in captured.out
    assert "Polling 'cryptominer' threat list for 5 hours..." in captured.out
    for i in range(5):
        timestamp = f"20250814{2+i:02d}"
        assert f"=== Poll {i+1}/5 | Timestamp: {timestamp} ===" in captured.out
        assert f"Request failed. Retrying..." in captured.out
        assert f"=== Cryptominer Threat List for Hour: {timestamp} ===" in captured.out
        assert "Total entries: 3" in captured.out
    assert mock_requests.call_count == 10
    assert mock_time_sleep.call_count == 4
    assert mock_time_sleep.call_args_list == [((5,),)] * 4
    expected_urls = [
        f"{BASE_URL}/threat_lists/cryptominer/20250814{2+i:02d}"
        for i in range(5)
        for _ in range(2)
    ]
    actual_urls = [call[0][0] for call in mock_requests.call_args_list]
    assert actual_urls == expected_urls


def test_main_all_failures(mock_requests, mock_time_sleep, mock_datetime, capsys):
    mock_response = MagicMock(status_code=429)
    mock_requests.side_effect = [mock_response] * 10

    main()

    captured = capsys.readouterr()
    assert "------ Threat List Hourly Polling -----" in captured.out
    assert "Starting polling at: 2025-08-14 02:52:00 UTC" in captured.out
    assert "Polling 'cryptominer' threat list for 5 hours..." in captured.out
    for i in range(5):
        timestamp = f"20250814{2+i:02d}"
        assert f"=== Poll {i+1}/5 | Timestamp: {timestamp} ===" in captured.out
        assert f"Request failed. Retrying..." in captured.out
        assert (
            f"Error fetching 'cryptominer' threat list for timestamp {timestamp}: Rate limit exceeded"
            in captured.out
        )
        assert "Note: This request might succeed if retried later." in captured.out
    assert mock_requests.call_count == 10
    assert mock_time_sleep.call_count == 4
    assert mock_time_sleep.call_args_list == [((5,),)] * 4
    expected_urls = [
        f"{BASE_URL}/threat_lists/cryptominer/20250814{2+i:02d}"
        for i in range(5)
        for _ in range(2)
    ]
    actual_urls = [call[0][0] for call in mock_requests.call_args_list]
    assert actual_urls == expected_urls


def test_print_hourly_threat_list_exception(monkeypatch, capsys):
    def mock_dumps(*args, **kwargs):
        raise RuntimeError("Mocked JSON serialization failure")

    monkeypatch.setattr("json.dumps", mock_dumps)

    response = {"success": True, "data": {"iocs": [{"id": 1, "threat": "malware"}]}}

    result = print_hourly_threat_list(response, "malware", "2025-08-21T12:00:00Z")

    captured = capsys.readouterr()

    assert result is False
    assert (
        "Error processing threat list: Mocked JSON serialization failure"
        in captured.out
    )
