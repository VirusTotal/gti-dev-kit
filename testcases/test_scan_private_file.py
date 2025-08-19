import pytest
from unittest.mock import patch, MagicMock
import requests
import json
from examples.file_and_url_scanning.private_scanning.scan_file import (
    make_api_request,
    get_upload_url,
    upload_file,
    poll_analysis_status,
    get_file_report,
    scan_private_file_and_get_report,
    print_scan_report,
    main,
    BASE_URL,
    MAX_DIRECT_UPLOAD_SIZE,
    POLLING_INTERVAL,
    MAX_POLLING_ATTEMPTS,
)
from testcases.constants import (
    SCAN_PRIVATE_FILE_UPLOAD_RESPONSE,
    SCAN_PRIVATE_FILE_ANALYSIS_IN_PROGRESS_RESPONSE,
    SCAN_PRIVATE_FILE_ANALYSIS_COMPLETED_RESPONSE,
    SCAN_PRIVATE_FILE_REPORT_RESPONSE,
    SCAN_PRIVATE_FILE_UPLOAD_URL_RESPONSE,
)


@pytest.fixture
def mock_requests():
    with patch("requests.request") as mock_request:
        yield mock_request


@pytest.fixture
def mock_open():
    with patch("builtins.open", new_callable=MagicMock) as mock_file:
        mock_file_obj = MagicMock()
        mock_file_obj.read = MagicMock(return_value=b"11111")
        mock_file.return_value.__enter__.return_value = mock_file_obj
        yield mock_file


@pytest.fixture
def mock_os_path():
    with patch("os.path") as mock_path:
        yield mock_path


@pytest.fixture
def mock_time_sleep():
    with patch("time.sleep") as mock_sleep:
        yield mock_sleep


def test_make_api_request_get_success(mock_requests):
    """Test successful GET API request."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = SCAN_PRIVATE_FILE_REPORT_RESPONSE
    mock_requests.return_value = mock_response

    result = make_api_request("GET", "private/files/test")

    assert result["success"] is True
    assert result["data"] == SCAN_PRIVATE_FILE_REPORT_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        "GET",
        f"{BASE_URL}/private/files/test",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        files=None,
        data=None,
        timeout=60,
    )


def test_make_api_request_post_success(mock_requests):
    """Test successful POST API request."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = SCAN_PRIVATE_FILE_UPLOAD_RESPONSE
    mock_requests.return_value = mock_response

    files = {"file": ("test.txt", MagicMock(), "application/octet-stream")}
    result = make_api_request("POST", "private/files", files=files)

    assert result["success"] is True
    assert result["data"] == SCAN_PRIVATE_FILE_UPLOAD_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        "POST",
        f"{BASE_URL}/private/files",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        files=files,
        data=None,
        timeout=60,
    )


def test_make_api_request_400_bad_request(mock_requests):
    """Test API request with 400 Bad Request."""
    mock_response = MagicMock(status_code=400)
    mock_requests.return_value = mock_response

    result = make_api_request("GET", "private/files/test")

    assert result["success"] is False
    assert result["error"] == "Bad request - invalid parameters"
    assert result["status_code"] == 400
    assert result["should_retry"] is False


def test_make_api_request_401_unauthorized(mock_requests):
    """Test API request with 401 Unauthorized."""
    mock_response = MagicMock(status_code=401)
    mock_requests.return_value = mock_response

    result = make_api_request("GET", "private/files/test")

    assert result["success"] is False
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["status_code"] == 401
    assert result["should_retry"] is False


def test_make_api_request_403_forbidden(mock_requests):
    """Test API request with 403 Forbidden."""
    mock_response = MagicMock(status_code=403)
    mock_requests.return_value = mock_response

    result = make_api_request("GET", "private/files/test")

    assert result["success"] is False
    assert result["error"] == "Forbidden - insufficient permissions"
    assert result["status_code"] == 403
    assert result["should_retry"] is False


def test_make_api_request_404_not_found(mock_requests):
    """Test API request with 404 Not Found."""
    mock_response = MagicMock(status_code=404)
    mock_requests.return_value = mock_response

    result = make_api_request("GET", "private/files/test")

    assert result["success"] is False
    assert result["error"] == "Resource not found"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_make_api_request_429_rate_limit(mock_requests):
    """Test API request with 429 Rate Limit Exceeded."""
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = make_api_request("GET", "private/files/test")

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_make_api_request_500_server_error(mock_requests):
    """Test API request with 500 Server Error."""
    mock_response = MagicMock(status_code=500)
    mock_requests.return_value = mock_response

    result = make_api_request("GET", "private/files/test")

    assert result["success"] is False
    assert result["error"] == "Server error (HTTP 500)"
    assert result["status_code"] == 500
    assert result["should_retry"] is True


def test_make_api_request_timeout(mock_requests):
    """Test API request with timeout."""
    mock_requests.side_effect = requests.exceptions.Timeout

    result = make_api_request("GET", "private/files/test")

    assert result["success"] is False
    assert result["error"] == "Request timed out"
    assert result["should_retry"] is True


def test_make_api_request_connection_error(mock_requests):
    """Test API request with connection error."""
    mock_requests.side_effect = requests.exceptions.ConnectionError

    result = make_api_request("GET", "private/files/test")

    assert result["success"] is False
    assert result["error"] == "Connection error - check your network"
    assert result["should_retry"] is True


def test_make_api_request_json_decode_error(mock_requests):
    """Test API request with JSON decode error."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_requests.return_value = mock_response

    result = make_api_request("GET", "private/files/test")

    assert result["success"] is False
    assert result["error"] == "Failed to parse JSON response: Invalid JSON"
    assert result["should_retry"] is False


def test_make_api_request_unexpected_error(mock_requests):
    """Test API request with unexpected error."""
    mock_requests.side_effect = requests.exceptions.RequestException("Unexpected error")

    result = make_api_request("GET", "private/files/test")

    assert result["success"] is False
    assert result["error"] == "Request failed: Unexpected error"
    assert result["should_retry"] is False


def test_get_upload_url_success(mock_requests):
    """Test successful retrieval of upload URL."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = SCAN_PRIVATE_FILE_UPLOAD_URL_RESPONSE
    mock_requests.return_value = mock_response

    result = get_upload_url()

    assert result["success"] is True
    assert result["data"] == SCAN_PRIVATE_FILE_UPLOAD_URL_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        "GET",
        f"{BASE_URL}/private/files/upload_url",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        files=None,
        data=None,
        timeout=60,
    )


def test_get_upload_url_rate_limit(mock_requests):
    """Test upload URL retrieval with rate limit error."""
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = get_upload_url()

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_get_upload_url_unauthorized(mock_requests):
    """Test upload URL retrieval with unauthorized error."""
    mock_response = MagicMock(status_code=401)
    mock_requests.return_value = mock_response

    result = get_upload_url()

    assert result["success"] is False
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["status_code"] == 401
    assert result["should_retry"] is False


def test_upload_file_direct_success(mock_requests, mock_open, mock_os_path):
    """Test successful direct file upload."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = SCAN_PRIVATE_FILE_UPLOAD_RESPONSE
    mock_requests.return_value = mock_response
    mock_os_path.exists.return_value = True
    mock_os_path.basename.return_value = "test.txt"
    mock_file_obj = mock_open.return_value.__enter__.return_value

    result = upload_file("test.txt")

    assert result["success"] is True
    assert result["data"] == SCAN_PRIVATE_FILE_UPLOAD_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        "POST",
        f"{BASE_URL}/private/files",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        files={"file": ("test.txt", mock_file_obj, "application/octet-stream")},
        data=None,
        timeout=60,
    )


def test_upload_file_not_found(mock_os_path):
    """Test upload with file not found."""
    mock_os_path.exists.return_value = False

    result = upload_file("test.txt")

    assert result["success"] is False
    assert result["error"] == "File not found: test.txt"
    assert result["should_retry"] is False


def test_upload_file_retryable_failure(mock_requests, mock_open, mock_os_path):
    """Test upload with retryable failure."""
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response
    mock_os_path.exists.return_value = True
    mock_os_path.basename.return_value = "test.txt"
    mock_file_obj = mock_open.return_value.__enter__.return_value

    result = upload_file("test.txt")

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True
    mock_requests.assert_called_once_with(
        "POST",
        f"{BASE_URL}/private/files",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        files={"file": ("test.txt", mock_file_obj, "application/octet-stream")},
        data=None,
        timeout=60,
    )


def test_upload_file_non_retryable_failure(mock_requests, mock_open, mock_os_path):
    """Test upload with non-retryable failure."""
    mock_response = MagicMock(status_code=401)
    mock_requests.return_value = mock_response
    mock_os_path.exists.return_value = True
    mock_os_path.basename.return_value = "test.txt"
    mock_file_obj = mock_open.return_value.__enter__.return_value

    result = upload_file("test.txt")

    assert result["success"] is False
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["status_code"] == 401
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        "POST",
        f"{BASE_URL}/private/files",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        files={"file": ("test.txt", mock_file_obj, "application/octet-stream")},
        data=None,
        timeout=60,
    )


def test_poll_analysis_status_completed(mock_requests):
    """Test polling with completed status."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = SCAN_PRIVATE_FILE_ANALYSIS_COMPLETED_RESPONSE
    mock_requests.return_value = mock_response

    result = poll_analysis_status(
        "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw=="
    )

    assert result["success"] is True
    assert result["data"] == SCAN_PRIVATE_FILE_ANALYSIS_COMPLETED_RESPONSE
    assert result["error"] is None
    assert result["should_retry"] is False
    mock_requests.assert_called_once_with(
        "GET",
        f"{BASE_URL}/private/analyses/MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw==",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        files=None,
        data=None,
        timeout=60,
    )


def test_poll_analysis_status_in_progress(mock_requests, mock_time_sleep):
    """Test polling with in-progress status."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = SCAN_PRIVATE_FILE_ANALYSIS_IN_PROGRESS_RESPONSE
    mock_requests.return_value = mock_response

    result = poll_analysis_status(
        "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw=="
    )

    assert result["success"] is False
    assert result["error"] == "Max polling attempts reached"
    assert result["should_retry"] is True
    assert mock_requests.call_count == MAX_POLLING_ATTEMPTS
    assert mock_time_sleep.call_count == MAX_POLLING_ATTEMPTS - 1


def test_poll_analysis_status_error(mock_requests):
    """Test polling with error status."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {
        "data": {
            "type": "private_analysis",
            "id": "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw==",
            "attributes": {"status": "error"},
        }
    }
    mock_requests.return_value = mock_response

    result = poll_analysis_status(
        "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw=="
    )

    assert result["success"] is False
    assert result["error"] == "Analysis error"
    assert result["should_retry"] is False


def test_poll_analysis_status_unsupported_file(mock_requests):
    """Test polling with unsupported file type."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {
        "data": {
            "type": "private_analysis",
            "id": "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw==",
            "attributes": {"status": "unsupported file type"},
        }
    }
    mock_requests.return_value = mock_response

    result = poll_analysis_status(
        "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw=="
    )

    assert result["success"] is False
    assert result["error"] == "Analysis unsupported file type"
    assert result["should_retry"] is False


def test_poll_analysis_status_corrupted_file(mock_requests):
    """Test polling with corrupted file status."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = {
        "data": {
            "type": "private_analysis",
            "id": "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw==",
            "attributes": {"status": "corrupted file"},
        }
    }
    mock_requests.return_value = mock_response

    result = poll_analysis_status(
        "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw=="
    )

    assert result["success"] is False
    assert result["error"] == "Analysis corrupted file"
    assert result["should_retry"] is False


def test_poll_analysis_status_api_failure(mock_requests):
    """Test polling with API failure."""
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = poll_analysis_status(
        "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw=="
    )

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_get_file_report_success(mock_requests):
    """Test successful file report retrieval."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = SCAN_PRIVATE_FILE_REPORT_RESPONSE
    mock_requests.return_value = mock_response

    result = get_file_report(
        "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d"
    )

    assert result["success"] is True
    assert result["data"] == SCAN_PRIVATE_FILE_REPORT_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False


def test_get_file_report_rate_limit(mock_requests):
    """Test file report retrieval with rate limit error."""
    mock_response = MagicMock(status_code=429)
    mock_requests.return_value = mock_response

    result = get_file_report(
        "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d"
    )

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_get_file_report_not_found(mock_requests):
    """Test file report retrieval with not found error."""
    mock_response = MagicMock(status_code=404)
    mock_requests.return_value = mock_response

    result = get_file_report(
        "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d"
    )

    assert result["success"] is False
    assert result["error"] == "Resource not found"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_scan_private_file_and_get_report_missing_file(mock_os_path, capsys):
    """Test scan with missing file."""
    mock_os_path.exists.return_value = False

    result = scan_private_file_and_get_report("test.txt")

    captured = capsys.readouterr()
    assert result is None
    assert "Error: File not found at test.txt" in captured.out


def test_scan_private_file_and_get_report_empty_file(mock_os_path, capsys):
    """Test scan with empty file."""
    mock_os_path.exists.return_value = True
    mock_os_path.getsize.return_value = 0

    result = scan_private_file_and_get_report("test.txt")

    captured = capsys.readouterr()
    assert result is None
    assert "Error: File is empty" in captured.out


def test_scan_private_file_and_get_report_upload_failure(
    mock_requests, mock_os_path, mock_open, capsys
):
    """Test scan with non-retryable upload failure."""
    mock_os_path.exists.return_value = True
    mock_os_path.getsize.return_value = 206
    mock_os_path.basename.return_value = "test.txt"
    mock_file_obj = mock_open.return_value.__enter__.return_value

    upload_response = MagicMock(status_code=401)
    mock_requests.return_value = upload_response

    result = scan_private_file_and_get_report("test.txt")

    captured = capsys.readouterr()
    assert result is None
    assert "Error uploading file: Unauthorized - invalid API key" in captured.out
    assert "Retrying upload..." not in captured.out


def test_scan_private_file_and_get_report_polling_timeout(
    mock_requests, mock_os_path, mock_open, mock_time_sleep, capsys
):
    """Test scan with polling timeout."""
    mock_os_path.exists.return_value = True
    mock_os_path.getsize.return_value = 206
    mock_os_path.basename.return_value = "test.txt"
    mock_file_obj = mock_open.return_value.__enter__.return_value

    upload_response = MagicMock(status_code=200)
    upload_response.json.return_value = SCAN_PRIVATE_FILE_UPLOAD_RESPONSE
    analysis_response = MagicMock(status_code=200)
    analysis_response.json.return_value = (
        SCAN_PRIVATE_FILE_ANALYSIS_IN_PROGRESS_RESPONSE
    )
    mock_requests.side_effect = [upload_response] + [
        analysis_response
    ] * MAX_POLLING_ATTEMPTS

    result = scan_private_file_and_get_report("test.txt")

    captured = capsys.readouterr()
    assert result is None
    assert "Max polling attempts reached" in captured.out
    assert mock_requests.call_count == 1 + MAX_POLLING_ATTEMPTS


def test_scan_private_file_and_get_report_no_analysis_id(
    mock_requests, mock_os_path, mock_open, capsys
):
    """Test scan with missing analysis ID."""
    mock_os_path.exists.return_value = True
    mock_os_path.getsize.return_value = 206
    mock_os_path.basename.return_value = "test.txt"
    mock_file_obj = mock_open.return_value.__enter__.return_value

    upload_response = MagicMock(status_code=200)
    upload_response.json.return_value = {"data": {}}
    mock_requests.return_value = upload_response

    result = scan_private_file_and_get_report("test.txt")

    captured = capsys.readouterr()
    assert result is None
    assert "Error: No analysis ID received" in captured.out


def test_scan_private_file_and_get_report_no_file_hash(
    mock_requests, mock_os_path, mock_open, capsys
):
    """Test scan with missing file hash."""
    mock_os_path.exists.return_value = True
    mock_os_path.getsize.return_value = 206
    mock_os_path.basename.return_value = "test.txt"
    mock_file_obj = mock_open.return_value.__enter__.return_value

    upload_response = MagicMock(status_code=200)
    upload_response.json.return_value = SCAN_PRIVATE_FILE_UPLOAD_RESPONSE
    analysis_response = MagicMock(status_code=200)
    analysis_response.json.return_value = {
        "data": {
            "type": "private_analysis",
            "id": "MzJhNzZlODhiMjc0NzBjMTg1ODI1NTY4MDg0NzgxOGM6YTA5NWI4ZDE1MTNhOWRkNDBhYjk5YTBmYzFmNjI4NWI6MTc1NTE0NDY1Nw==",
            "attributes": {"status": "completed"},
            "meta": {},
        }
    }
    mock_requests.side_effect = [upload_response, analysis_response]

    result = scan_private_file_and_get_report("test.txt")

    captured = capsys.readouterr()
    assert result is None
    assert "Error: No file hash received" in captured.out


def test_print_scan_report_clean(capsys):
    """Test printing scan report with clean verdict."""
    print_scan_report(SCAN_PRIVATE_FILE_REPORT_RESPONSE)
    captured = capsys.readouterr()

    assert "--- Scan Report ---" in captured.out
    assert (
        "File SHA-256: f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d"
        in captured.out
    )
    assert "Verdict: CLEAN" in captured.out
    assert "Malicious detections" not in captured.out
    assert "GTI Assessment:" in captured.out
    assert "verdict: {'value': 'VERDICT_UNDETECTED'}" in captured.out
    assert (
        "description: This indicator did not match our detection criteria and there is currently no evidence of malicious activity."
        in captured.out
    )
    assert "====== Full JSON Report ========" in captured.out
    assert (
        json.dumps(SCAN_PRIVATE_FILE_REPORT_RESPONSE["data"], indent=2) in captured.out
    )


def test_print_scan_report_malicious(capsys):
    """Test printing scan report with malicious verdict."""
    malicious_report = {
        "data": {
            "id": "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d",
            "type": "private_file",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "undetected": 90,
                    "harmless": 5,
                },
                "gti_assessment": {
                    "verdict": {"value": "VERDICT_MALICIOUS"},
                    "threat_score": {"value": 80},
                },
            },
        }
    }
    print_scan_report(malicious_report)
    captured = capsys.readouterr()

    assert "Verdict: MALICIOUS" in captured.out
    assert "Malicious detections: 2" in captured.out
    assert "GTI Assessment:" in captured.out
    assert "verdict: {'value': 'VERDICT_MALICIOUS'}" in captured.out


def test_print_scan_report_no_gti_assessment(capsys):
    """Test printing scan report without GTI assessment."""
    report = {
        "data": {
            "id": "f0de2e62ca270423aecf386b578668a3bcebd300f0bc794e667f6467d4792a3d",
            "type": "private_file",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "undetected": 94,
                    "harmless": 5,
                }
            },
        }
    }
    print_scan_report(report)
    captured = capsys.readouterr()

    assert "Verdict: MALICIOUS" in captured.out
    assert "Malicious detections: 1" in captured.out
    assert "GTI Assessment:" not in captured.out


def test_print_scan_report_invalid_report(capsys):
    """Test printing invalid or empty report."""
    print_scan_report(None)
    captured = capsys.readouterr()

    assert "Invalid or empty scan report" in captured.out


def test_main_missing_file(mock_os_path, mock_open, capsys):
    """Test main function with missing file."""
    mock_os_path.exists.return_value = False
    mock_file_obj = mock_open.return_value.__enter__.return_value
    mock_file_obj.write = MagicMock()

    main()

    captured = capsys.readouterr()
    assert "Error: File not found at dummy_private_file.txt" in captured.out
    assert "Scan failed or no results available" in captured.out
    mock_open.assert_any_call("dummy_private_file.txt", "w")
    mock_file_obj.write.assert_called_once_with("11111")


def test_main_polling_timeout(
    mock_requests, mock_os_path, mock_open, mock_time_sleep, capsys
):
    """Test main function with polling timeout."""
    mock_os_path.exists.return_value = True
    mock_os_path.getsize.return_value = 206
    mock_os_path.basename.return_value = "dummy_private_file.txt"
    mock_file_obj = mock_open.return_value.__enter__.return_value
    mock_file_obj.write = MagicMock()

    upload_response = MagicMock(status_code=200)
    upload_response.json.return_value = SCAN_PRIVATE_FILE_UPLOAD_RESPONSE
    analysis_response = MagicMock(status_code=200)
    analysis_response.json.return_value = (
        SCAN_PRIVATE_FILE_ANALYSIS_IN_PROGRESS_RESPONSE
    )
    mock_requests.side_effect = [upload_response] + [
        analysis_response
    ] * MAX_POLLING_ATTEMPTS

    main()

    captured = capsys.readouterr()
    assert "Max polling attempts reached" in captured.out
    assert "Scan failed or no results available" in captured.out
    assert mock_requests.call_count == 1 + MAX_POLLING_ATTEMPTS
    mock_open.assert_any_call("dummy_private_file.txt", "w")
    mock_file_obj.write.assert_called_once_with("11111")
