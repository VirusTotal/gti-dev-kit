import pytest
from unittest.mock import patch, MagicMock
import requests
from examples.threat_list_and_ioc_stream_ingestion.ingest_ioc_stream_with_polling import (
    make_api_request,
    get_ioc_stream_objects,
    print_ioc_stream,
    poll_ioc_stream,
    main,
    BASE_URL,
    GTI_API_KEY,
    X_TOOL_HEADER,
)
from testcases.constants import IOC_STREAM_API_RESPONSE


@pytest.fixture
def mock_requests():
    with patch("requests.get") as mock_request:
        yield mock_request


@pytest.fixture
def mock_time_sleep():
    with patch("time.sleep") as mock_sleep:
        yield mock_sleep


def test_make_api_request_success(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = IOC_STREAM_API_RESPONSE
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream", params={})

    assert result["success"] is True
    assert result["data"] == IOC_STREAM_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        f"{BASE_URL}/ioc_stream",
        headers={"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
        params={},
        timeout=60,
    )


def test_make_api_request_with_cursor(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = IOC_STREAM_API_RESPONSE
    mock_requests.return_value = mock_response
    cursor = IOC_STREAM_API_RESPONSE["meta"]["cursor"]
    params = {"cursor": cursor}

    result = make_api_request(f"{BASE_URL}/ioc_stream", params=params)

    assert result["success"] is True
    assert result["data"] == IOC_STREAM_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        f"{BASE_URL}/ioc_stream",
        headers={"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
        params=params,
        timeout=60,
    )


def test_make_api_request_400_bad_request(mock_requests):
    mock_response = MagicMock(status_code=400)
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream", params={})

    assert result["success"] is False
    assert result["error"] == "Bad request - invalid parameters"
    assert result["status_code"] == 400
    assert result["should_retry"] is False


def test_make_api_request_401_unauthorized(mock_requests):
    mock_response = MagicMock(status_code=401)
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream", params={})

    assert result["success"] is False
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["status_code"] == 401
    assert result["should_retry"] is False


def test_make_api_request_403_forbidden(mock_requests):
    mock_response = MagicMock(status_code=403)
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream", params={})

    assert result["success"] is False
    assert result["error"] == "Forbidden - insufficient permissions"
    assert result["status_code"] == 403
    assert result["should_retry"] is False


def test_make_api_request_404_not_found(mock_requests):
    mock_response = MagicMock(status_code=404)
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream", params={})

    assert result["success"] is False
    assert result["error"] == "Endpoint not found"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_make_api_request_429_rate_limit(mock_requests):
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream", params={})

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_make_api_request_500_server_error(mock_requests):
    mock_response = MagicMock(status_code=500)
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream", params={})

    assert result["success"] is False
    assert result["error"] == "Server error (HTTP 500)"
    assert result["status_code"] == 500
    assert result["should_retry"] is True


def test_make_api_request_timeout(mock_requests):
    mock_requests.side_effect = requests.exceptions.Timeout

    result = make_api_request(f"{BASE_URL}/ioc_stream", params={})

    assert result["success"] is False
    assert result["error"] == "Request timed out"
    assert result["should_retry"] is True


def test_make_api_request_connection_error(mock_requests):
    mock_requests.side_effect = requests.exceptions.ConnectionError

    result = make_api_request(f"{BASE_URL}/ioc_stream", params={})

    assert result["success"] is False
    assert result["error"] == "Connection error - check your network"
    assert result["should_retry"] is True


def test_make_api_request_json_decode_error(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream", params={})

    assert result["success"] is False
    assert result["error"] == "Failed to parse JSON response: Invalid JSON"
    assert result["should_retry"] is False


def test_make_api_request_unexpected_error(mock_requests):
    mock_requests.side_effect = requests.exceptions.RequestException("Unexpected error")

    result = make_api_request(f"{BASE_URL}/ioc_stream", params={})

    assert result["success"] is False
    assert result["error"] == "Request failed: Unexpected error"
    assert result["should_retry"] is False


def test_get_ioc_stream_objects_success_no_cursor(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = IOC_STREAM_API_RESPONSE
    mock_requests.return_value = mock_response

    result = get_ioc_stream_objects()

    assert result["success"] is True
    assert result["data"] == IOC_STREAM_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        f"{BASE_URL}/ioc_stream",
        headers={"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
        params={},
        timeout=60,
    )


def test_get_ioc_stream_objects_success_with_cursor(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = IOC_STREAM_API_RESPONSE
    mock_requests.return_value = mock_response
    cursor = IOC_STREAM_API_RESPONSE["meta"]["cursor"]

    result = get_ioc_stream_objects(cursor)

    assert result["success"] is True
    assert result["data"] == IOC_STREAM_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        f"{BASE_URL}/ioc_stream",
        headers={"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
        params={"cursor": cursor},
        timeout=60,
    )


def test_get_ioc_stream_objects_rate_limit(mock_requests):
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = get_ioc_stream_objects()

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_get_ioc_stream_objects_not_found(mock_requests):
    mock_response = MagicMock(status_code=404)
    mock_requests.return_value = mock_response

    result = get_ioc_stream_objects()

    assert result["success"] is False
    assert result["error"] == "Endpoint not found"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_print_ioc_stream_failure(capsys):
    response = {
        "success": False,
        "data": None,
        "error": "Rate limit exceeded",
        "status_code": 429,
        "should_retry": True,
    }

    next_cursor = print_ioc_stream(response)

    captured = capsys.readouterr()
    assert "Error fetching IOC stream: Rate limit exceeded" in captured.out
    assert "Note: This request might succeed if retried later." in captured.out
    assert next_cursor is None


def test_print_ioc_stream_invalid_data(capsys):
    response = {
        "success": True,
        "data": {},
        "error": None,
        "status_code": 200,
        "should_retry": False,
    }

    next_cursor = print_ioc_stream(response)

    captured = capsys.readouterr()
    assert "No new IOCs received in this poll." in captured.out
    assert next_cursor is None


def test_poll_ioc_stream_failure_no_retry(mock_requests, mock_time_sleep, capsys):
    mock_response = MagicMock(status_code=401)
    mock_requests.side_effect = [mock_response] * 3

    poll_ioc_stream(polls=3, interval=5)

    captured = capsys.readouterr()
    for i in range(3):
        assert f"=== Poll {i+1}/3 ===" in captured.out
        assert (
            "Error fetching IOC stream: Unauthorized - invalid API key" in captured.out
        )
    assert "Waiting 5 seconds before next poll..." in captured.out
    assert mock_requests.call_count == 3
    assert mock_time_sleep.call_count == 2
    assert mock_time_sleep.call_args_list == [((5,),)] * 2
    expected_calls = [
        (
            (f"{BASE_URL}/ioc_stream",),
            {
                "headers": {"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
                "params": {},
                "timeout": 60,
            },
        ),
        (
            (f"{BASE_URL}/ioc_stream",),
            {
                "headers": {"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
                "params": {},
                "timeout": 60,
            },
        ),
        (
            (f"{BASE_URL}/ioc_stream",),
            {
                "headers": {"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
                "params": {},
                "timeout": 60,
            },
        ),
    ]
    actual_calls = [(call[0], call[1]) for call in mock_requests.call_args_list]
    assert actual_calls == expected_calls


def test_poll_ioc_stream_failure_with_retry(mock_requests, mock_time_sleep, capsys):
    mock_response = MagicMock(status_code=429)
    mock_requests.side_effect = [mock_response] * 3

    poll_ioc_stream(polls=3, interval=5)

    captured = capsys.readouterr()
    for i in range(3):
        assert f"=== Poll {i+1}/3 ===" in captured.out
        assert "Error fetching IOC stream: Rate limit exceeded" in captured.out
        assert "Note: This request might succeed if retried later." in captured.out
    assert "Waiting 5 seconds before next poll..." in captured.out
    assert mock_requests.call_count == 3
    assert mock_time_sleep.call_count == 2
    assert mock_time_sleep.call_args_list == [((5,),)] * 2
    expected_calls = [
        (
            (f"{BASE_URL}/ioc_stream",),
            {
                "headers": {"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
                "params": {},
                "timeout": 60,
            },
        ),
        (
            (f"{BASE_URL}/ioc_stream",),
            {
                "headers": {"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
                "params": {},
                "timeout": 60,
            },
        ),
        (
            (f"{BASE_URL}/ioc_stream",),
            {
                "headers": {"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
                "params": {},
                "timeout": 60,
            },
        ),
    ]
    actual_calls = [(call[0], call[1]) for call in mock_requests.call_args_list]
    assert actual_calls == expected_calls


def test_main_failure_no_retry(mock_requests, mock_time_sleep, capsys):
    mock_response = MagicMock(status_code=401)
    mock_requests.side_effect = [mock_response] * 3

    main()

    captured = capsys.readouterr()
    assert "Starting IOC Stream Polling..." in captured.out
    for i in range(3):
        assert f"=== Poll {i+1}/3 ===" in captured.out
        assert (
            "Error fetching IOC stream: Unauthorized - invalid API key" in captured.out
        )
    assert "Waiting 5 seconds before next poll..." in captured.out
    assert mock_requests.call_count == 3
    assert mock_time_sleep.call_count == 2
    assert mock_time_sleep.call_args_list == [((5,),)] * 2
    expected_calls = [
        (
            (f"{BASE_URL}/ioc_stream",),
            {
                "headers": {"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
                "params": {},
                "timeout": 60,
            },
        ),
        (
            (f"{BASE_URL}/ioc_stream",),
            {
                "headers": {"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
                "params": {},
                "timeout": 60,
            },
        ),
        (
            (f"{BASE_URL}/ioc_stream",),
            {
                "headers": {"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
                "params": {},
                "timeout": 60,
            },
        ),
    ]
    actual_calls = [(call[0], call[1]) for call in mock_requests.call_args_list]
    assert actual_calls == expected_calls


def test_main_failure_with_retry(mock_requests, mock_time_sleep, capsys):
    mock_response = MagicMock(status_code=429)
    mock_requests.side_effect = [mock_response] * 3

    main()

    captured = capsys.readouterr()
    assert "Starting IOC Stream Polling..." in captured.out
    for i in range(3):
        assert f"=== Poll {i+1}/3 ===" in captured.out
        assert "Error fetching IOC stream: Rate limit exceeded" in captured.out
        assert "Note: This request might succeed if retried later." in captured.out
    assert "Waiting 5 seconds before next poll..." in captured.out
    assert mock_requests.call_count == 3
    assert mock_time_sleep.call_count == 2
    assert mock_time_sleep.call_args_list == [((5,),)] * 2
    expected_calls = [
        (
            (f"{BASE_URL}/ioc_stream",),
            {
                "headers": {"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
                "params": {},
                "timeout": 60,
            },
        ),
        (
            (f"{BASE_URL}/ioc_stream",),
            {
                "headers": {"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
                "params": {},
                "timeout": 60,
            },
        ),
        (
            (f"{BASE_URL}/ioc_stream",),
            {
                "headers": {"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
                "params": {},
                "timeout": 60,
            },
        ),
    ]
    actual_calls = [(call[0], call[1]) for call in mock_requests.call_args_list]
    assert actual_calls == expected_calls
