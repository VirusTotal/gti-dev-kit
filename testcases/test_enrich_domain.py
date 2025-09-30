import pytest
import os
import json
import requests
from unittest.mock import patch, mock_open, MagicMock
from examples.automatic_and_manual_enrichment.enrich_domain import (
    get_cache_filename,
    make_api_request,
    get_domain_report,
    print_domain_report,
    CACHE_DIR,
    BASE_URL,
)
from testcases.constants import DOMAIN, ENRICH_DOMAIN_API_RESPONSE


MOCK_CACHE_FILE = os.path.join(CACHE_DIR, f"domain_{DOMAIN}_cache_file.json")


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


def test_get_cache_filename():
    """Test cache filename generation."""
    expected = os.path.join(CACHE_DIR, f"domain_{DOMAIN}_cache_file.json")
    result = get_cache_filename(DOMAIN)
    assert result == expected, f"Expected cache filename {expected}, got {result}"


def test_make_api_request_success(mock_requests_get):
    """Test successful API request."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_DOMAIN_API_RESPONSE
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is True
    assert result["data"] == ENRICH_DOMAIN_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests_get.assert_called_once()


def test_make_api_request_400_bad_request(mock_requests_get):
    """Test API request with 400 Bad Request."""
    mock_response = MagicMock(status_code=400)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is False
    assert result["error"] == "Bad request - invalid parameters"
    assert result["status_code"] == 400
    assert result["should_retry"] is False


def test_make_api_request_401_unauthorized(mock_requests_get):
    """Test API request with 401 Unauthorized."""
    mock_response = MagicMock(status_code=401)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is False
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["status_code"] == 401
    assert result["should_retry"] is False


def test_make_api_request_403_unauthorized(mock_requests_get):
    """Test API request with 403 Unauthorized."""
    mock_response = MagicMock(status_code=403)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is False
    assert result["error"] == "Forbidden - insufficient permissions"
    assert result["status_code"] == 403
    assert result["should_retry"] is False


def test_make_api_request_404_unauthorized(mock_requests_get):
    """Test API request with 404 Unauthorized."""
    mock_response = MagicMock(status_code=404)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is False
    assert result["error"] == "Resource not found"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_make_api_request_429_rate_limit(mock_requests_get):
    """Test API request with 429 Rate Limit Exceeded."""
    mock_response = MagicMock(status_code=429)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_make_api_request_500_server_error(mock_requests_get):
    """Test API request with 500 Server Error."""
    mock_response = MagicMock(status_code=500)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is False
    assert result["error"] == "Server error (HTTP 500)"
    assert result["status_code"] == 500
    assert result["should_retry"] is True


def test_make_api_request_unexpected_http_status(mock_requests_get):
    """Test API request with 500 Server Error."""
    mock_response = MagicMock(status_code=900)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is False
    assert result["error"] == "Unexpected HTTP status: 900"
    assert result["status_code"] == 900
    assert result["should_retry"] is False


def test_make_api_request_timeout(mock_requests_get):
    """Test API request with timeout."""
    mock_requests_get.side_effect = requests.exceptions.Timeout

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is False
    assert result["error"] == "Request timed out"
    assert result["should_retry"] is True


def test_make_api_request_unexpected_error(mock_requests_get):
    """Test API request with unexpected error."""
    mock_requests_get.side_effect = requests.exceptions.RequestException(
        "Unexpected error"
    )

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is False
    assert result["error"] == "Request failed: Unexpected error"
    assert result["should_retry"] is False


def test_make_api_request_connection_error(mock_requests_get):
    """Test API request with connection error."""
    mock_requests_get.side_effect = requests.exceptions.ConnectionError

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is False
    assert result["error"] == "Connection error - check your network"
    assert result["should_retry"] is True


def test_make_api_request_json_decode_error(mock_requests_get):
    """Test API request with JSON decode error."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is False
    assert result["error"] == "Failed to parse JSON response: Invalid JSON"
    assert result["status_code"] == 200
    assert result["should_retry"] is False


def test_make_api_unexpected_error(mock_requests_get):
    """Test API request with connection error."""
    mock_requests_get.side_effect = Exception("Unexpected error")

    result = make_api_request(f"{BASE_URL}/domains/{DOMAIN}")

    assert result["success"] is False
    assert result["error"] == "Unexpected error: Unexpected error"
    assert result["should_retry"] is False


def test_get_domain_report_from_cache(mock_os_path_exists, mock_open_file):
    """Test fetching domain report from cache."""
    mock_os_path_exists.return_value = True
    mock_open_file().read.return_value = json.dumps(ENRICH_DOMAIN_API_RESPONSE)

    result = get_domain_report(DOMAIN)

    assert result["success"] is True
    assert result["data"] == ENRICH_DOMAIN_API_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_open_file.assert_called_with(MOCK_CACHE_FILE, "r")


def test_get_domain_report_cache_io_error(
    mock_os_path_exists, mock_open_file, mock_requests_get
):
    """Test cache read error, falling back to API."""
    mock_os_path_exists.return_value = True
    mock_open_file.side_effect = IOError("Cannot read file")
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_DOMAIN_API_RESPONSE
    mock_requests_get.return_value = mock_response

    result = get_domain_report(DOMAIN)

    assert result["success"] is True
    assert result["data"] == ENRICH_DOMAIN_API_RESPONSE
    mock_requests_get.assert_called_once()


def test_get_domain_report_no_cache_api_success(
    mock_os_path_exists,
    mock_requests_get,
    mock_open_file,
    mock_os_makedirs,
    mock_json_dump,
):
    """Test fetching domain report from API with successful cache save."""
    mock_os_path_exists.return_value = False
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_DOMAIN_API_RESPONSE
    mock_requests_get.return_value = mock_response

    result = get_domain_report(DOMAIN)

    assert result["success"] is True
    assert result["data"] == ENRICH_DOMAIN_API_RESPONSE
    mock_os_makedirs.assert_called_with(CACHE_DIR, exist_ok=True)
    mock_open_file.assert_called_with(MOCK_CACHE_FILE, "w")
    mock_json_dump.assert_called_once_with(
        ENRICH_DOMAIN_API_RESPONSE, mock_open_file(), indent=2
    )


def test_get_domain_report_no_cache_cache_write_error(
    mock_os_path_exists, mock_requests_get, mock_open_file, mock_os_makedirs
):
    """Test API success but cache write failure."""
    mock_os_path_exists.return_value = False
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_DOMAIN_API_RESPONSE
    mock_requests_get.return_value = mock_response
    mock_open_file.side_effect = IOError("Cannot write file")

    result = get_domain_report(DOMAIN)

    assert result["success"] is True
    assert result["data"] == ENRICH_DOMAIN_API_RESPONSE
    mock_os_makedirs.assert_called_with(CACHE_DIR, exist_ok=True)
    mock_open_file.assert_called_with(MOCK_CACHE_FILE, "w")


def test_print_domain_report_success(capsys):
    """Test printing a successful domain report."""
    print_domain_report({"success": True, "data": ENRICH_DOMAIN_API_RESPONSE}, DOMAIN)
    captured = capsys.readouterr()

    assert f"Domain Threat Intelligence Report for {DOMAIN}" in captured.out
    assert "Verdict: Clean" in captured.out
    assert "GTI Assessment:" in captured.out
    assert "verdict: {'value': 'VERDICT_BENIGN'}" in captured.out
    assert "Full JSON Report" in captured.out


def test_print_domain_report_failed_request(capsys):
    """Test printing a failed domain report."""
    domain_report = {"success": False, "error": "API error", "should_retry": True}
    print_domain_report(domain_report, DOMAIN)
    captured = capsys.readouterr()

    assert f"Error fetching report for {DOMAIN}: API error" in captured.out
    assert "Note: This request might succeed if retried later." in captured.out


def test_print_domain_report_malicious(capsys):
    """Test printing a report with malicious detections."""
    malicious_report = ENRICH_DOMAIN_API_RESPONSE.copy()
    malicious_report["data"]["attributes"]["last_analysis_stats"]["malicious"] = 5
    print_domain_report({"success": True, "data": malicious_report}, DOMAIN)
    captured = capsys.readouterr()

    assert "Verdict: Malicious" in captured.out
    assert "Malicious detections: 5" in captured.out


def test_print_domain_report_no_gti_assessment(capsys):
    """Test printing a report with no GTI assessment."""
    no_gti_report = ENRICH_DOMAIN_API_RESPONSE.copy()
    no_gti_report["data"]["attributes"]["gti_assessment"] = {}
    print_domain_report({"success": True, "data": no_gti_report}, DOMAIN)
    captured = capsys.readouterr()

    assert "No GTI assessment available" in captured.out


def test_print_domain_report_invalid_data(capsys):
    """Test printing a report with invalid data structure."""
    print_domain_report({"success": True, "data": {}}, DOMAIN)
    captured = capsys.readouterr()

    assert "No GTI assessment available" in captured.out


def test_print_domain_report_exception(capsys):
    bad_report = {"success": True, "data": "this_should_be_a_dict"}

    print_domain_report(bad_report, "example.com")

    captured = capsys.readouterr()

    assert "Error processing report for example.com:" in captured.out

    assert "'str' object has no attribute 'get'" in captured.out


def test_main_retry_logic(mock_os_path_exists, mock_requests_get, capsys):
    """Test main function retry logic on failed request."""
    mock_os_path_exists.return_value = False
    mock_response_fail = MagicMock(status_code=429)
    mock_response_success = MagicMock(status_code=200)
    mock_response_success.json.return_value = ENRICH_DOMAIN_API_RESPONSE
    mock_requests_get.side_effect = [mock_response_fail, mock_response_success]

    with patch(
        "examples.automatic_and_manual_enrichment.enrich_domain.get_domain_report"
    ) as mock_get_domain_report:
        mock_get_domain_report.side_effect = [
            {"success": False, "error": "Rate limit exceeded", "should_retry": True},
            {"success": True, "data": ENRICH_DOMAIN_API_RESPONSE},
        ]
        from examples.automatic_and_manual_enrichment.enrich_domain import main

        main()

    captured = capsys.readouterr()
    assert "Retrying failed request..." in captured.out
