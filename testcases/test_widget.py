import pytest
from unittest.mock import patch, MagicMock
import requests
from examples.gti_widget.widget import (
    make_widget_request,
    print_widget_info,
    main,
    BASE_URL,
)
from testcases.constants import GTI_WIDGET_API_RESPONSE


@pytest.fixture
def mock_requests_get():
    with patch("requests.get") as mock_get:
        yield mock_get


def test_make_widget_request_success(mock_requests_get):
    """Test successful widget request."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = GTI_WIDGET_API_RESPONSE
    mock_requests_get.return_value = mock_response

    observable = "1.1.1.1"
    result = make_widget_request(observable)

    assert result["success"] is True
    assert result["data"] == GTI_WIDGET_API_RESPONSE["data"]
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests_get.assert_called_once_with(
        BASE_URL,
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        params={"query": observable},
        timeout=60,
    )


def test_make_widget_request_400_bad_request(mock_requests_get):
    """Test widget request with 400 Bad Request."""
    mock_response = MagicMock(status_code=400)
    mock_requests_get.return_value = mock_response

    observable = "invalid_ip"
    result = make_widget_request(observable)

    assert result["success"] is False
    assert (
        result["error"]
        == "Bad request - the observable may be malformed or unsupported."
    )
    assert result["status_code"] == 400
    assert result["should_retry"] is False


def test_make_widget_request_401_unauthorized(mock_requests_get):
    """Test widget request with 401 Unauthorized."""
    mock_response = MagicMock(status_code=401)
    mock_requests_get.return_value = mock_response

    observable = "1.1.1.1"
    result = make_widget_request(observable)

    assert result["success"] is False
    assert result["error"] == "Unauthorized - check your API key."
    assert result["status_code"] == 401
    assert result["should_retry"] is False


def test_make_widget_request_403_forbidden(mock_requests_get):
    """Test widget request with 403 Forbidden."""
    mock_response = MagicMock(status_code=403)
    mock_requests_get.return_value = mock_response

    observable = "1.1.1.1"
    result = make_widget_request(observable)

    assert result["success"] is False
    assert (
        result["error"]
        == "Forbidden - API key not permitted to access widget endpoint."
    )
    assert result["status_code"] == 403
    assert result["should_retry"] is False


def test_make_widget_request_429_rate_limit(mock_requests_get):
    """Test widget request with 429 Rate Limit Exceeded."""
    mock_response = MagicMock(status_code=429)
    mock_requests_get.return_value = mock_response

    observable = "1.1.1.1"
    result = make_widget_request(observable)

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded - retry later."
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_make_widget_request_500_server_error(mock_requests_get):
    """Test widget request with 500 Server Error."""
    mock_response = MagicMock(status_code=500)
    mock_requests_get.return_value = mock_response

    observable = "1.1.1.1"
    result = make_widget_request(observable)

    assert result["success"] is False
    assert result["error"] == "Server error (HTTP 500)."
    assert result["status_code"] == 500
    assert result["should_retry"] is True


def test_make_api_request_unexpected_http_status(mock_requests_get):
    """Test API request with 500 Server Error."""
    mock_response = MagicMock(status_code=900)
    mock_requests_get.return_value = mock_response

    observable = "1.1.1.1"
    result = make_widget_request(observable)

    assert result["success"] is False
    assert result["error"] == "Unexpected HTTP status: 900"
    assert result["status_code"] == 900
    assert result["should_retry"] is False


def test_make_widget_request_timeout(mock_requests_get):
    """Test widget request with timeout."""
    mock_requests_get.side_effect = requests.exceptions.Timeout

    observable = "1.1.1.1"
    result = make_widget_request(observable)

    assert result["success"] is False
    assert result["error"] == "Request timed out"
    assert result["should_retry"] is True


def test_make_widget_request_request_exception(mock_requests_get):
    """Test widget request with request exception."""
    mock_requests_get.side_effect = requests.exceptions.RequestException(
        "Request failed"
    )

    observable = "1.1.1.1"
    result = make_widget_request(observable)

    assert result["success"] is False
    assert result["error"] == "Request error: Request failed"
    assert result["should_retry"] is True


def test_make_widget_request_unexpected_error(mock_requests_get):
    """Test widget request with unexpected error."""
    mock_requests_get.side_effect = Exception("Unexpected error")

    observable = "1.1.1.1"
    result = make_widget_request(observable)

    assert result["success"] is False
    assert result["error"] == "Unexpected error: Unexpected error"
    assert result["should_retry"] is False


def test_print_widget_info_success(capsys):
    """Test printing successful widget info."""
    response = {"success": True, "data": GTI_WIDGET_API_RESPONSE["data"]}
    observable = "1.1.1.1"
    print_widget_info(response, observable)
    captured = capsys.readouterr()

    assert "=== Widget Info for Observable: 1.1.1.1 ===" in captured.out
    assert (
        "Widget URL       : https://www.virustotal.com/ui/widget/html/MS4xLjEuMXx8aXBfYWRkcmVzc3x8eyJiZDEiOiAiIzRkNjM4NSIsICJiZzEiOiAiIzMxM2Q1YSIsICJiZzIiOiAiIzIyMmM0MiIsICJmZzEiOiAiI2ZmZmZmZiIsICJ0eXBlIjogImRlZmF1bHQifXx8ZnVsbHx8Zm91bmR8fHYzfHwxNzU1MDk3MzI4fHw2YWJhMTQxYjYyYWI5MmM3YmUxNjIzZTdhYjE2NzhjNDA1MTlhOTY0MTI5N2U2ZjA3NmU2MzI2MTFmYTM5Mjdk"
        in captured.out
    )
    assert "Detection Ratio  : 0 / 94" in captured.out


def test_print_widget_info_failed_request(capsys):
    """Test printing failed widget request."""
    response = {
        "success": False,
        "error": "Rate limit exceeded - retry later.",
        "should_retry": True,
    }
    observable = "1.1.1.1"
    print_widget_info(response, observable)
    captured = capsys.readouterr()

    assert "[!] Failed to retrieve widget for: 1.1.1.1" in captured.out
    assert "Error: Rate limit exceeded - retry later." in captured.out
    assert "Note: This request might succeed if retried later." in captured.out


def test_print_widget_info_missing_ratio_fields(capsys):
    """Test printing widget info with missing detection ratio fields."""
    response = {
        "success": True,
        "data": {
            "id": "1.1.1.1",
            "url": "https://www.virustotal.com/ui/widget/html/test",
            "detection_ratio": {},
            "type": "ip_address",
            "found": True,
        },
    }
    observable = "1.1.1.1"
    print_widget_info(response, observable)
    captured = capsys.readouterr()

    assert "=== Widget Info for Observable: 1.1.1.1 ===" in captured.out
    assert (
        "Widget URL       : https://www.virustotal.com/ui/widget/html/test"
        in captured.out
    )
    assert "Detection Ratio  : N/A / N/A" in captured.out


def test_print_widget_info_empty_data(capsys):
    """Test printing widget info with empty data."""
    response = {"success": True, "data": {}}
    observable = "1.1.1.1"
    print_widget_info(response, observable)
    captured = capsys.readouterr()

    assert "=== Widget Info for Observable: 1.1.1.1 ===" in captured.out
    assert "Widget URL       : N/A" in captured.out
    assert "Detection Ratio  : N/A / N/A" in captured.out


def test_main_success(mock_requests_get, capsys):
    """Test main function with successful response."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = GTI_WIDGET_API_RESPONSE
    mock_requests_get.return_value = mock_response

    from examples.gti_widget.widget import main

    main()

    captured = capsys.readouterr()
    assert "Requesting VT Widget for observable: 1.1.1.1 ..." in captured.out
    assert "=== Widget Info for Observable: 1.1.1.1 ===" in captured.out
    assert (
        "Widget URL       : https://www.virustotal.com/ui/widget/html/MS4xLjEuMXx8aXBfYWRkcmVzc3x8eyJiZDEiOiAiIzRkNjM4NSIsICJiZzEiOiAiIzMxM2Q1YSIsICJiZzIiOiAiIzIyMmM0MiIsICJmZzEiOiAiI2ZmZmZmZiIsICJ0eXBlIjogImRlZmF1bHQifXx8ZnVsbHx8Zm91bmR8fHYzfHwxNzU1MDk3MzI4fHw2YWJhMTQxYjYyYWI5MmM3YmUxNjIzZTdhYjE2NzhjNDA1MTlhOTY0MTI5N2U2ZjA3NmU2MzI2MTFmYTM5Mjdk"
        in captured.out
    )
    assert "Detection Ratio  : 0 / 94" in captured.out
    assert mock_requests_get.call_count == 1


def test_main_with_retry(mock_requests_get, capsys):
    """Test main function with retry on failed request."""
    mock_response_fail = MagicMock(status_code=429)
    mock_response_success = MagicMock(status_code=200)
    mock_response_success.json.return_value = GTI_WIDGET_API_RESPONSE
    mock_requests_get.side_effect = [mock_response_fail, mock_response_success]

    from examples.gti_widget.widget import main

    main()

    captured = capsys.readouterr()
    assert "Requesting VT Widget for observable: 1.1.1.1 ..." in captured.out
    assert "Retrying after failure..." in captured.out
    assert "=== Widget Info for Observable: 1.1.1.1 ===" in captured.out
    assert "Detection Ratio  : 0 / 94" in captured.out
    assert mock_requests_get.call_count == 2


def test_main_failed_no_retry(mock_requests_get, capsys):
    """Test main function with failed request (no retry)."""
    mock_response = MagicMock(status_code=401)
    mock_requests_get.return_value = mock_response

    from examples.gti_widget.widget import main

    main()

    captured = capsys.readouterr()
    assert "Requesting VT Widget for observable: 1.1.1.1 ..." in captured.out
    assert "[!] Failed to retrieve widget for: 1.1.1.1" in captured.out
    assert "Error: Unauthorized - check your API key." in captured.out
    assert "Note: This request might succeed if retried later." not in captured.out
    assert mock_requests_get.call_count == 1


def test_main_missing_data_fields(mock_requests_get, capsys):
    """Test main function with missing data fields."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {"data": {}}
    mock_requests_get.return_value = mock_response

    from examples.gti_widget.widget import main

    main()

    captured = capsys.readouterr()
    assert "Requesting VT Widget for observable: 1.1.1.1 ..." in captured.out
    assert "=== Widget Info for Observable: 1.1.1.1 ===" in captured.out
    assert "Widget URL       : N/A" in captured.out
    assert "Detection Ratio  : N/A / N/A" in captured.out
    assert mock_requests_get.call_count == 1
