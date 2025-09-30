import pytest
from unittest.mock import patch, MagicMock
import requests
from examples.asm.ingest_asm_issues_with_polling import (
    make_api_request,
    search_asm_issues,
    print_asm_results,
    poll_asm_issues,
    BASE_URL,
)
from testcases.constants import ASM_ISSUES_API_RESPONSE


@pytest.fixture
def mock_requests_get():
    with patch("requests.get") as mock_get:
        yield mock_get


@pytest.fixture
def mock_time_sleep():
    with patch("time.sleep") as mock_sleep:
        yield mock_sleep


def test_make_api_request_success(mock_requests_get):
    """Test successful API request."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ASM_ISSUES_API_RESPONSE
    mock_requests_get.return_value = mock_response

    query_string = "severity:5"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000, "page_token": ""})

    assert result["success"] is True
    assert result["data"] == ASM_ISSUES_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests_get.assert_called_once_with(
        url,
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        params={"page_size": 1000, "page_token": ""},
        timeout=60,
    )


def test_make_api_request_400_bad_request(mock_requests_get):
    """Test API request with 400 Bad Request."""
    mock_response = MagicMock(status_code=400)
    mock_requests_get.return_value = mock_response

    query_string = "invalid:query"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000, "page_token": ""})

    assert result["success"] is False
    assert result["error"] == "Bad request - invalid query parameters"
    assert result["status_code"] == 400
    assert result["should_retry"] is False


def test_make_api_request_401_unauthorized(mock_requests_get):
    """Test API request with 401 Unauthorized."""
    mock_response = MagicMock(status_code=401)
    mock_requests_get.return_value = mock_response

    query_string = "severity:5"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000, "page_token": ""})

    assert result["success"] is False
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["status_code"] == 401
    assert result["should_retry"] is False


def test_make_api_request_403_forbidden(mock_requests_get):
    """Test API request with 403 Forbidden."""
    mock_response = MagicMock(status_code=403)
    mock_requests_get.return_value = mock_response

    query_string = "severity:5"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000, "page_token": ""})

    assert result["success"] is False
    assert result["error"] == "Forbidden - insufficient permissions"
    assert result["status_code"] == 403
    assert result["should_retry"] is False


def test_make_api_request_404_not_found(mock_requests_get):
    """Test API request with 404 Not Found."""
    mock_response = MagicMock(status_code=404)
    mock_requests_get.return_value = mock_response

    query_string = "severity:5"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000, "page_token": ""})

    assert result["success"] is False
    assert result["error"] == "Endpoint not found"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_make_api_request_429_rate_limit(mock_requests_get):
    """Test API request with 429 Rate Limit Exceeded."""
    mock_response = MagicMock(status_code=429)
    mock_requests_get.return_value = mock_response

    query_string = "severity:5"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000, "page_token": ""})

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_make_api_request_500_server_error(mock_requests_get):
    """Test API request with 500 Server Error."""
    mock_response = MagicMock(status_code=500)
    mock_requests_get.return_value = mock_response

    query_string = "severity:5"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000, "page_token": ""})

    assert result["success"] is False
    assert result["error"] == "Server error (HTTP 500)"
    assert result["status_code"] == 500
    assert result["should_retry"] is True


def test_make_api_request_unexpected_http_status(mock_requests_get):
    """Test API request with 500 Server Error."""
    mock_response = MagicMock(status_code=900)
    mock_requests_get.return_value = mock_response

    query_string = "severity:5"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000})

    assert result["success"] is False
    assert result["error"] == "Unexpected HTTP status: 900"
    assert result["status_code"] == 900
    assert result["should_retry"] is False


def test_make_api_request_timeout(mock_requests_get):
    """Test API request with timeout."""
    mock_requests_get.side_effect = requests.exceptions.Timeout

    query_string = "severity:5"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000, "page_token": ""})

    assert result["success"] is False
    assert result["error"] == "Request timed out"
    assert result["should_retry"] is True


def test_make_api_request_connection_error(mock_requests_get):
    """Test API request with connection error."""
    mock_requests_get.side_effect = requests.exceptions.ConnectionError

    query_string = "severity:5"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000, "page_token": ""})

    assert result["success"] is False
    assert result["error"] == "Connection error - check your network"
    assert result["should_retry"] is True


def test_make_api_unexpected_error(mock_requests_get):
    """Test API request with connection error."""
    mock_requests_get.side_effect = Exception("Unexpected error")

    query_string = "severity:5"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000})

    assert result["success"] is False
    assert result["error"] == "Unexpected error: Unexpected error"
    assert result["should_retry"] is False


def test_make_api_request_json_decode_error(mock_requests_get):
    """Test API request with JSON decode error."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_requests_get.return_value = mock_response

    query_string = "severity:5"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000, "page_token": ""})

    assert result["success"] is False
    assert result["error"] == "Failed to parse JSON response: Invalid JSON"
    assert result["should_retry"] is False


def test_make_api_request_unexpected_error(mock_requests_get):
    """Test API request with unexpected error."""
    mock_requests_get.side_effect = requests.exceptions.RequestException(
        "Unexpected error"
    )

    query_string = "severity:5"
    url = f"{BASE_URL}/asm/search/issues/{query_string}"
    result = make_api_request(url, params={"page_size": 1000, "page_token": ""})

    assert result["success"] is False
    assert result["error"] == "Request failed: Unexpected error"
    assert result["should_retry"] is False


def test_search_asm_issues_success(mock_requests_get):
    """Test successful ASM issues search with page token."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ASM_ISSUES_API_RESPONSE
    mock_requests_get.return_value = mock_response

    query_string = "severity:5"
    page_token = "test_token"
    result = search_asm_issues(query_string, page_token)

    assert result["success"] is True
    assert result["data"] == ASM_ISSUES_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests_get.assert_called_once_with(
        f"{BASE_URL}/asm/search/issues/{query_string}",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        params={"page_size": 1000, "page_token": "test_token"},
        timeout=60,
    )


def test_search_asm_issues_no_page_token(mock_requests_get):
    """Test successful ASM issues search without page token."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ASM_ISSUES_API_RESPONSE
    mock_requests_get.return_value = mock_response

    query_string = "severity:5"
    result = search_asm_issues(query_string)

    assert result["success"] is True
    assert result["data"] == ASM_ISSUES_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests_get.assert_called_once_with(
        f"{BASE_URL}/asm/search/issues/{query_string}",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        params={"page_size": 1000, "page_token": ""},
        timeout=60,
    )


def test_search_asm_issues_failed(mock_requests_get):
    """Test failed ASM issues search."""
    mock_response = MagicMock(status_code=429)
    mock_requests_get.return_value = mock_response

    query_string = "severity:5"
    result = search_asm_issues(query_string)

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_print_asm_results_success(capsys):
    """Test printing successful ASM results."""
    result = print_asm_results({"success": True, "data": ASM_ISSUES_API_RESPONSE})
    captured = capsys.readouterr()

    assert result == ASM_ISSUES_API_RESPONSE["result"]["next_page_token"]
    assert "Found 4 ASM issues (first 3):" in captured.out
    assert (
        '"pretty_name": "Insecure Cookie (Missing \'HttpOnly\' Attribute)"'
        in captured.out
    )
    assert '"entity_name": "https://advertising.amazon.ca:443"' in captured.out
    assert '"entity_name": "http://buy.amazon.com:80"' in captured.out
    assert '"entity_name": "https://cc.amazon.com:443"' in captured.out
    assert '"entity_name": "https://advertising.amazon.ca:443"' in captured.out


def test_print_asm_results_failed_request(capsys):
    """Test printing failed ASM request."""
    response = {
        "success": False,
        "error": "Rate limit exceeded",
        "should_retry": True,
        "data": {"result": {"next_page_token": "retry_token"}},
    }
    result = print_asm_results(response)
    captured = capsys.readouterr()

    assert result == "retry_token"
    assert "Error searching ASM issues: Rate limit exceeded" in captured.out
    assert "Note: This request might succeed if retried later." in captured.out


def test_print_asm_results_formatting_error(capsys):
    """Test printing with formatting error."""
    response = {"success": True, "data": None}
    result = print_asm_results(response)
    captured = capsys.readouterr()

    assert result is False
    assert "Error formatting results:" in captured.out


def test_poll_asm_issues_success(mock_requests_get, mock_time_sleep, capsys):
    """Test polling ASM issues with successful responses."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ASM_ISSUES_API_RESPONSE
    mock_requests_get.return_value = mock_response

    poll_asm_issues("severity:5", polls=2, interval=5)
    captured = capsys.readouterr()

    assert "=== Poll 1/2 ===" in captured.out
    assert "=== Poll 2/2 ===" in captured.out
    assert "Found 4 ASM issues (first 3):" in captured.out
    assert "Waiting 5 seconds before next poll..." in captured.out
    assert mock_requests_get.call_count == 2
    assert mock_time_sleep.call_count == 1
    mock_time_sleep.assert_called_with(5)


def test_poll_asm_issues_with_retry(mock_requests_get, mock_time_sleep, capsys):
    """Test polling ASM issues with retry on failed request."""
    mock_response_fail = MagicMock(status_code=429)
    mock_response_success = MagicMock(status_code=200)
    mock_response_success.json.return_value = ASM_ISSUES_API_RESPONSE
    mock_requests_get.side_effect = [
        mock_response_fail,
        mock_response_success,
        mock_response_success,
    ]

    poll_asm_issues("severity:5", polls=2, interval=5)
    captured = capsys.readouterr()

    assert "=== Poll 1/2 ===" in captured.out
    assert "Retrying failed request..." in captured.out
    assert "=== Poll 2/2 ===" in captured.out
    assert "Found 4 ASM issues (first 3):" in captured.out
    assert "Waiting 5 seconds before next poll..." in captured.out
    assert mock_requests_get.call_count == 3
    assert mock_time_sleep.call_count == 1
    mock_time_sleep.assert_called_with(5)


def test_poll_asm_issues_no_hits(mock_requests_get, mock_time_sleep, capsys):
    """Test polling ASM issues with no hits."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {
        "success": True,
        "result": {"hits": [], "next_page_token": ""},
    }
    mock_requests_get.return_value = mock_response

    poll_asm_issues("severity:5", polls=2, interval=5)
    captured = capsys.readouterr()

    assert "=== Poll 1/2 ===" in captured.out
    assert "=== Poll 2/2 ===" in captured.out
    assert "No ASM issues found matching the query." in captured.out
    assert "Waiting 5 seconds before next poll..." in captured.out
    assert mock_requests_get.call_count == 2
    assert mock_time_sleep.call_count == 1


def test_main(mock_requests_get, mock_time_sleep, capsys):
    """Test main function with polling."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ASM_ISSUES_API_RESPONSE
    mock_requests_get.return_value = mock_response

    from examples.asm.ingest_asm_issues_with_polling import main

    main()

    captured = capsys.readouterr()
    assert "Starting ASM Issues Polling..." in captured.out
    assert "=== Poll 1/3 ===" in captured.out
    assert "=== Poll 2/3 ===" in captured.out
    assert "=== Poll 3/3 ===" in captured.out
    assert "Found 4 ASM issues (first 3):" in captured.out
    assert "Waiting 5 seconds before next poll..." in captured.out
    assert mock_requests_get.call_count == 3
    assert mock_time_sleep.call_count == 2
