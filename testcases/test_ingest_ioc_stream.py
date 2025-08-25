import pytest
from unittest.mock import patch, MagicMock
import json
import requests
from examples.threat_list_and_ioc_stream_ingestion.ingest_ioc_stream import (
    make_api_request,
    get_ioc_stream,
    print_ioc_stream,
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


def test_make_api_request_success(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = IOC_STREAM_API_RESPONSE
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is True
    assert result["data"] == IOC_STREAM_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        f"{BASE_URL}/ioc_stream",
        headers={"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
        params=None,
        timeout=60,
    )


def test_make_api_request_with_params(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = IOC_STREAM_API_RESPONSE
    mock_requests.return_value = mock_response
    params = {"cursor": IOC_STREAM_API_RESPONSE["meta"]["cursor"]}

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

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is False
    assert result["error"] == "Bad request - invalid parameters"
    assert result["status_code"] == 400
    assert result["should_retry"] is False


def test_make_api_request_401_unauthorized(mock_requests):
    mock_response = MagicMock(status_code=401)
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is False
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["status_code"] == 401
    assert result["should_retry"] is False


def test_make_api_request_403_forbidden(mock_requests):
    mock_response = MagicMock(status_code=403)
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is False
    assert result["error"] == "Forbidden - insufficient permissions"
    assert result["status_code"] == 403
    assert result["should_retry"] is False


def test_make_api_request_404_not_found(mock_requests):
    mock_response = MagicMock(status_code=404)
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is False
    assert result["error"] == "Endpoint not found"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_make_api_request_429_rate_limit(mock_requests):
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_make_api_request_500_server_error(mock_requests):
    mock_response = MagicMock(status_code=500)
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is False
    assert result["error"] == "Server error (HTTP 500)"
    assert result["status_code"] == 500
    assert result["should_retry"] is True


def test_make_api_request_unexpected_http_status(mock_requests):
    """Test API request with 500 Server Error."""
    mock_response = MagicMock(status_code=900)
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is False
    assert result["error"] == "Unexpected HTTP status: 900"
    assert result["status_code"] == 900
    assert result["should_retry"] is False


def test_make_api_unexpected_error(mock_requests):
    """Test API request with connection error."""
    mock_requests.side_effect = Exception("Unexpected error")

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is False
    assert result["error"] == "Unexpected error: Unexpected error"
    assert result["should_retry"] is False


def test_make_api_request_timeout(mock_requests):
    mock_requests.side_effect = requests.exceptions.Timeout

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is False
    assert result["error"] == "Request timed out"
    assert result["should_retry"] is True


def test_make_api_request_connection_error(mock_requests):
    mock_requests.side_effect = requests.exceptions.ConnectionError

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is False
    assert result["error"] == "Connection error - check your network"
    assert result["should_retry"] is True


def test_make_api_request_json_decode_error(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_requests.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is False
    assert result["error"] == "Failed to parse JSON response: Invalid JSON"
    assert result["should_retry"] is False


def test_make_api_request_unexpected_error(mock_requests):
    mock_requests.side_effect = requests.exceptions.RequestException("Unexpected error")

    result = make_api_request(f"{BASE_URL}/ioc_stream")

    assert result["success"] is False
    assert result["error"] == "Request failed: Unexpected error"
    assert result["should_retry"] is False


def test_get_ioc_stream_success(mock_requests):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = IOC_STREAM_API_RESPONSE
    mock_requests.return_value = mock_response

    result = get_ioc_stream()

    assert result["success"] is True
    assert result["data"] == IOC_STREAM_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        f"{BASE_URL}/ioc_stream",
        headers={"x-apikey": GTI_API_KEY, "x-tool": X_TOOL_HEADER},
        params=None,
        timeout=60,
    )


def test_get_ioc_stream_rate_limit(mock_requests):
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = get_ioc_stream()

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_get_ioc_stream_not_found(mock_requests):
    mock_response = MagicMock(status_code=404)
    mock_requests.return_value = mock_response

    result = get_ioc_stream()

    assert result["success"] is False
    assert result["error"] == "Endpoint not found"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_print_ioc_stream_success(capsys):
    response = {
        "success": True,
        "data": IOC_STREAM_API_RESPONSE,
        "error": None,
        "status_code": 200,
        "should_retry": False,
    }

    print_ioc_stream(response, max_display=1)

    captured = capsys.readouterr()
    assert "Received 1 new IOCs" in captured.out
    assert "Displaying top 1 IOCs:" in captured.out
    assert json.dumps(IOC_STREAM_API_RESPONSE["data"][:1], indent=2) in captured.out


def test_print_ioc_stream_empty_iocs(capsys):
    response = {
        "success": True,
        "data": {"data": []},
        "error": None,
        "status_code": 200,
        "should_retry": False,
    }

    print_ioc_stream(response)

    captured = capsys.readouterr()
    assert "No new IOCs received." in captured.out


def test_print_ioc_stream_failure(capsys):
    response = {
        "success": False,
        "data": None,
        "error": "Rate limit exceeded",
        "status_code": 429,
        "should_retry": True,
    }

    print_ioc_stream(response)

    captured = capsys.readouterr()
    assert "Error fetching IOC stream: Rate limit exceeded" in captured.out
    assert "This request might succeed if retried later." in captured.out


def test_print_ioc_stream_invalid_data(capsys):
    response = {
        "success": True,
        "data": {},
        "error": None,
        "status_code": 200,
        "should_retry": False,
    }

    print_ioc_stream(response)

    captured = capsys.readouterr()
    assert "No new IOCs received." in captured.out


def test_main_success(mock_requests, capsys):
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = IOC_STREAM_API_RESPONSE
    mock_requests.side_effect = [mock_response]

    main()

    captured = capsys.readouterr()
    assert (
        "Fetching latest IOC stream from Google Threat Intelligence..." in captured.out
    )
    assert "Received 1 new IOCs" in captured.out
    assert "Displaying top 1 IOCs:" in captured.out
    assert json.dumps(IOC_STREAM_API_RESPONSE["data"][:1], indent=2) in captured.out
    assert mock_requests.call_count == 1
    assert mock_requests.call_args_list[0][0][0] == f"{BASE_URL}/ioc_stream"


def test_main_retry_on_failure(mock_requests, capsys):
    mock_response_fail = MagicMock(status_code=429)
    mock_response_success = MagicMock(status_code=200)
    mock_response_success.json.return_value = IOC_STREAM_API_RESPONSE
    mock_requests.side_effect = [mock_response_fail, mock_response_success]

    main()

    captured = capsys.readouterr()
    assert (
        "Fetching latest IOC stream from Google Threat Intelligence..." in captured.out
    )
    assert "Retrying failed request..." in captured.out
    assert "Received 1 new IOCs" in captured.out
    assert "Displaying top 1 IOCs:" in captured.out
    assert json.dumps(IOC_STREAM_API_RESPONSE["data"][:1], indent=2) in captured.out
    assert mock_requests.call_count == 2
    assert mock_requests.call_args_list[0][0][0] == f"{BASE_URL}/ioc_stream"
    assert mock_requests.call_args_list[1][0][0] == f"{BASE_URL}/ioc_stream"


def test_main_failure_no_retry(mock_requests, capsys):
    mock_response = MagicMock(status_code=401)
    mock_requests.side_effect = [mock_response]

    main()

    captured = capsys.readouterr()
    assert (
        "Fetching latest IOC stream from Google Threat Intelligence..." in captured.out
    )
    assert "Error fetching IOC stream: Unauthorized - invalid API key" in captured.out
    assert "Retrying failed request..." not in captured.out
    assert mock_requests.call_count == 1
    assert mock_requests.call_args_list[0][0][0] == f"{BASE_URL}/ioc_stream"


def test_main_failure_with_retry(mock_requests, capsys):
    mock_response = MagicMock(status_code=429)
    mock_requests.side_effect = [mock_response, mock_response]

    main()

    captured = capsys.readouterr()
    assert (
        "Fetching latest IOC stream from Google Threat Intelligence..." in captured.out
    )
    assert "Retrying failed request..." in captured.out
    assert "Error fetching IOC stream: Rate limit exceeded" in captured.out
    assert "This request might succeed if retried later." in captured.out
    assert mock_requests.call_count == 2
    assert mock_requests.call_args_list[0][0][0] == f"{BASE_URL}/ioc_stream"
    assert mock_requests.call_args_list[1][0][0] == f"{BASE_URL}/ioc_stream"


def test_print_ioc_stream_exception_case():
    """Test that print_ioc_stream handles exceptions properly."""
    malformed_response = {"success": True, "data": {"data": [{"invalid": "data"}]}}

    with patch(
        "examples.threat_list_and_ioc_stream_ingestion.ingest_ioc_stream.json.dumps"
    ) as mock_dumps:  
        mock_dumps.side_effect = Exception("JSON serialization failed")

        with patch("builtins.print") as mock_print:
            print_ioc_stream(malformed_response)

            mock_print.assert_any_call("Error printing IOCs: JSON serialization failed")


def test_print_ioc_stream_json_dumps_exception():
    """Test exception handling specifically for json.dumps failure."""
    valid_response = {
        "success": True,
        "data": {"data": [{"ioc": "malicious.com", "type": "domain"}]},
    }

    with patch(
        "examples.threat_list_and_ioc_stream_ingestion.ingest_ioc_stream.json.dumps"
    ) as mock_dumps:  
        mock_dumps.side_effect = Exception("Custom JSON error")

        with patch("builtins.print") as mock_print:
            print_ioc_stream(valid_response)

            mock_print.assert_any_call("Error printing IOCs: Custom JSON error")
