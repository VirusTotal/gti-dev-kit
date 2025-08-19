import pytest
from unittest.mock import patch, MagicMock
import requests
from examples.dtm.ingest_dtm_alerts import (
    make_api_request,
    list_dtm_alerts,
    print_dtm_results,
    BASE_URL,
)
from testcases.constants import DTM_ALERTS_API_RESPONSE


@pytest.fixture
def mock_requests_get():
    with patch("requests.get") as mock_get:
        yield mock_get


def test_make_api_request_success(mock_requests_get):
    """Test successful API request."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = DTM_ALERTS_API_RESPONSE
    mock_requests_get.return_value = mock_response

    params = {"size": 100, "since": "2025-08-01T00:00:00Z"}
    url = f"{BASE_URL}/dtm/alerts"
    result = make_api_request(url, params=params)

    assert result["success"] is True
    assert result["data"] == DTM_ALERTS_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is bool(False)
    mock_requests_get.assert_called_once_with(
        url,
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        params=params,
        timeout=60,
    )


def test_make_api_request_400_bad_request(mock_requests_get):
    """Test API request with 400 Bad Request."""
    mock_response = MagicMock(status_code=400)
    mock_requests_get.return_value = mock_response

    params = {"size": "invalid"}
    url = f"{BASE_URL}/dtm/alerts"
    result = make_api_request(url, params=params)

    assert result["success"] is bool(False)
    assert result["error"] == "Bad request - invalid parameters"
    assert result["status_code"] == 400
    assert result["should_retry"] is bool(False)


def test_make_api_request_401_unauthorized(mock_requests_get):
    """Test API request with 401 Unauthorized."""
    mock_response = MagicMock(status_code=401)
    mock_requests_get.return_value = mock_response

    params = {"size": 100}
    url = f"{BASE_URL}/dtm/alerts"
    result = make_api_request(url, params=params)

    assert result["success"] is bool(False)
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["status_code"] == 401
    assert result["should_retry"] is bool(False)


def test_make_api_request_403_forbidden(mock_requests_get):
    """Test API request with 403 Forbidden."""
    mock_response = MagicMock(status_code=403)
    mock_requests_get.return_value = mock_response

    params = {"size": 100}
    url = f"{BASE_URL}/dtm/alerts"
    result = make_api_request(url, params=params)

    assert result["success"] is bool(False)
    assert result["error"] == "Forbidden - insufficient permissions"
    assert result["status_code"] == 403
    assert result["should_retry"] is bool(False)


def test_make_api_request_404_not_found(mock_requests_get):
    """Test API request with 404 Not Found."""
    mock_response = MagicMock(status_code=404)
    mock_requests_get.return_value = mock_response

    params = {"size": 100}
    url = f"{BASE_URL}/dtm/alerts"
    result = make_api_request(url, params=params)

    assert result["success"] is bool(False)
    assert result["error"] == "Endpoint not found"
    assert result["status_code"] == 404
    assert result["should_retry"] is bool(False)


def test_make_api_request_429_rate_limit(mock_requests_get):
    """Test API request with 429 Rate Limit Exceeded."""
    mock_response = MagicMock(status_code=429)
    mock_requests_get.return_value = mock_response

    params = {"size": 100}
    url = f"{BASE_URL}/dtm/alerts"
    result = make_api_request(url, params=params)

    assert result["success"] is bool(False)
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_make_api_request_500_server_error(mock_requests_get):
    """Test API request with 500 Server Error."""
    mock_response = MagicMock(status_code=500)
    mock_requests_get.return_value = mock_response

    params = {"size": 100}
    url = f"{BASE_URL}/dtm/alerts"
    result = make_api_request(url, params=params)

    assert result["success"] is bool(False)
    assert result["error"] == "Server error (HTTP 500)"
    assert result["status_code"] == 500
    assert result["should_retry"] is True


def test_make_api_request_timeout(mock_requests_get):
    """Test API request with timeout."""
    mock_requests_get.side_effect = requests.exceptions.Timeout

    params = {"size": 100}
    url = f"{BASE_URL}/dtm/alerts"
    result = make_api_request(url, params=params)

    assert result["success"] is bool(False)
    assert result["error"] == "Request timed out"
    assert result["should_retry"] is True


def test_make_api_request_connection_error(mock_requests_get):
    """Test API request with connection error."""
    mock_requests_get.side_effect = requests.exceptions.ConnectionError

    params = {"size": 100}
    url = f"{BASE_URL}/dtm/alerts"
    result = make_api_request(url, params=params)

    assert result["success"] is bool(False)
    assert result["error"] == "Connection error - check your network"
    assert result["should_retry"] is True


def test_make_api_request_json_decode_error(mock_requests_get):
    """Test API request with JSON decode error."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_requests_get.return_value = mock_response

    params = {"size": 100}
    url = f"{BASE_URL}/dtm/alerts"
    result = make_api_request(url, params=params)

    assert result["success"] is bool(False)
    assert result["error"] == "Failed to parse JSON response: Invalid JSON"
    assert result["should_retry"] is bool(False)


def test_make_api_request_unexpected_error(mock_requests_get):
    """Test API request with unexpected error."""
    mock_requests_get.side_effect = requests.exceptions.RequestException(
        "Unexpected error"
    )

    params = {"size": 100}
    url = f"{BASE_URL}/dtm/alerts"
    result = make_api_request(url, params=params)

    assert result["success"] is bool(False)
    assert result["error"] == "Request failed: Unexpected error"
    assert result["should_retry"] is bool(False)


def test_list_dtm_alerts_success(mock_requests_get):
    """Test successful DTM alerts fetch."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = DTM_ALERTS_API_RESPONSE
    mock_requests_get.return_value = mock_response

    params = {"size": 100, "since": "2025-08-01T00:00:00Z"}
    result = list_dtm_alerts(params)

    assert result["success"] is True
    assert result["data"] == DTM_ALERTS_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is bool(False)
    mock_requests_get.assert_called_once_with(
        f"{BASE_URL}/dtm/alerts",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        params=params,
        timeout=60,
    )


def test_list_dtm_alerts_no_params(mock_requests_get):
    """Test DTM alerts fetch without params."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = DTM_ALERTS_API_RESPONSE
    mock_requests_get.return_value = mock_response

    result = list_dtm_alerts({})

    assert result["success"] is True
    assert result["data"] == DTM_ALERTS_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is bool(False)
    mock_requests_get.assert_called_once_with(
        f"{BASE_URL}/dtm/alerts",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        params={},
        timeout=60,
    )


def test_list_dtm_alerts_failed(mock_requests_get):
    """Test failed DTM alerts fetch."""
    mock_response = MagicMock(status_code=429)
    mock_requests_get.return_value = mock_response

    params = {"size": 100}
    result = list_dtm_alerts(params)

    assert result["success"] is bool(False)
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_print_dtm_results_success(capsys):
    """Test printing successful DTM results."""
    response = {"success": True, "data": DTM_ALERTS_API_RESPONSE}
    result = print_dtm_results(response, max_display=3)
    captured = capsys.readouterr()

    assert result is True
    assert "Found 2 DTM alerts:" in captured.out


def test_print_dtm_results_no_alerts(capsys):
    """Test printing DTM results with no alerts."""
    response = {"success": True, "data": {"alerts": []}}
    result = print_dtm_results(response)
    captured = capsys.readouterr()

    assert result is True
    assert "No DTM alerts found matching the criteria." in captured.out


def test_print_dtm_results_failed_request(capsys):
    """Test printing failed DTM request."""
    response = {
        "success": bool(False),
        "error": "Rate limit exceeded",
        "should_retry": True,
    }
    result = print_dtm_results(response)
    captured = capsys.readouterr()

    assert result is bool(False)
    assert "Error fetching DTM alerts: Rate limit exceeded" in captured.out
    assert "Note: This request might succeed if retried later." in captured.out


def test_print_dtm_results_formatting_error(capsys):
    """Test printing with formatting error."""
    response = {"success": True, "data": None} 
    result = print_dtm_results(response)
    captured = capsys.readouterr()

    assert result is bool(False)
    assert "Error formatting results:" in captured.out


def test_main_success(mock_requests_get, capsys):
    """Test main function with successful response."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = DTM_ALERTS_API_RESPONSE
    mock_requests_get.return_value = mock_response

    from examples.dtm.ingest_dtm_alerts import main

    main()

    captured = capsys.readouterr()
    assert "Fetching DTM alerts..." in captured.out
    assert "Found 2 DTM alerts:" in captured.out
    assert mock_requests_get.call_count == 1
    mock_requests_get.assert_called_with(
        f"{BASE_URL}/dtm/alerts",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        params={
            "refs": bool(False),
            "size": 100,
            "order": "desc",
            "since": "2025-08-01T00:00:00Z",
            "monitor_id": [],
            "status": [],
            "alert_type": [],
            "tags": [],
            "match_value": [],
            "severity": [],
            "mscore_gte": 0,
            "search": "",
        },
        timeout=60,
    )


def test_main_with_retry(mock_requests_get, capsys):
    """Test main function with retry on failed request."""
    mock_response_fail = MagicMock(status_code=429)
    mock_response_success = MagicMock(status_code=200)
    mock_response_success.json.return_value = DTM_ALERTS_API_RESPONSE
    mock_requests_get.side_effect = [mock_response_fail, mock_response_success]

    from examples.dtm.ingest_dtm_alerts import main

    main()

    captured = capsys.readouterr()
    assert "Fetching DTM alerts..." in captured.out
    assert "Retrying failed request..." in captured.out
    assert "Found 2 DTM alerts:" in captured.out
    assert mock_requests_get.call_count == 2


def test_main_no_alerts(mock_requests_get, capsys):
    """Test main function with no alerts."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {"alerts": []}
    mock_requests_get.return_value = mock_response

    from examples.dtm.ingest_dtm_alerts import main

    main()

    captured = capsys.readouterr()
    assert "Fetching DTM alerts..." in captured.out
    assert "No DTM alerts found matching the criteria." in captured.out
    assert mock_requests_get.call_count == 1
