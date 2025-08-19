import pytest
from unittest.mock import patch, MagicMock
from requests.exceptions import Timeout, ConnectionError
from typing import Dict

from examples.file_and_url_scanning.public_scanning.scan_file import ( 
    make_api_request,
    get_upload_url,
    upload_file,
    poll_analysis_status,
    get_file_report,
    scan_file_and_get_report,
    print_scan_report,
    MAX_DIRECT_UPLOAD_SIZE,
    POLLING_INTERVAL,
    MAX_POLLING_ATTEMPTS,
)

from testcases.constants import (
    SCAN_PUBLIC_FILE_ANALYSIS_RESPONSE,
    SCAN_PUBLIC_FILE_REPORT_RESPONSE,
    SCAN_PUBLIC_FILE_RESPONSE,
)


def mock_successful_response(data: Dict = None, status_code: int = 200):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = data or {}
    return mock_resp


def mock_error_response(status_code: int = 400):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = {"error": "Test error"}
    return mock_resp


@pytest.fixture
def mock_file(tmp_path):
    file_path = tmp_path / "test_file.txt"
    file_path.write_text("Test content")
    return file_path


@patch("requests.request")
def test_make_api_request_success(mock_request):
    mock_request.return_value = mock_successful_response({"key": "value"})
    result = make_api_request("GET", "test_endpoint")
    assert result["success"] is True
    assert result["data"] == {"key": "value"}
    assert result["error"] is None
    assert result["status_code"] == 200


@patch("requests.request")
def test_make_api_request_400_error(mock_request):
    mock_request.return_value = mock_error_response(400)
    result = make_api_request("GET", "test_endpoint")
    assert result["success"] is False
    assert result["error"] == "Bad request - invalid parameters"
    assert result["should_retry"] is False


@patch("requests.request")
def test_make_api_request_401_error(mock_request):
    mock_request.return_value = mock_error_response(401)
    result = make_api_request("GET", "test_endpoint")
    assert result["success"] is False
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["should_retry"] is False


@patch("requests.request")
def test_make_api_request_429_error(mock_request):
    mock_request.return_value = mock_error_response(429)
    result = make_api_request("GET", "test_endpoint")
    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["should_retry"] is True


@patch("requests.request")
def test_make_api_request_500_error(mock_request):
    mock_request.return_value = mock_error_response(500)
    result = make_api_request("GET", "test_endpoint")
    assert result["success"] is False
    assert "Server error" in result["error"]
    assert result["should_retry"] is True


@patch("requests.request")
def test_make_api_request_timeout(mock_request):
    mock_request.side_effect = Timeout()
    result = make_api_request("GET", "test_endpoint")
    assert result["success"] is False
    assert result["error"] == "Request timed out"
    assert result["should_retry"] is True


@patch("requests.request")
def test_make_api_request_connection_error(mock_request):
    mock_request.side_effect = ConnectionError()
    result = make_api_request("GET", "test_endpoint")
    assert result["success"] is False
    assert result["error"] == "Connection error - check your network"
    assert result["should_retry"] is True


@patch("requests.request")
def test_make_api_request_unexpected_error(mock_request):
    mock_request.side_effect = Exception("Unexpected error")
    result = make_api_request("GET", "test_endpoint")
    assert result["success"] is False
    assert "Unexpected error" in result["error"]
    assert result["should_retry"] is False


@patch("examples.file_and_url_scanning.public_scanning.scan_file.make_api_request")
def test_get_upload_url_success(mock_make_request):
    mock_make_request.return_value = {
        "success": True,
        "data": {"data": "https://upload.url"},
    }
    result = get_upload_url()
    assert result["success"] is True
    assert "https://upload.url" in result["data"]["data"]


@patch("examples.file_and_url_scanning.public_scanning.scan_file.make_api_request")
def test_upload_file_success(mock_make_request, mock_file):
    mock_make_request.return_value = {
        "success": True,
        "data": SCAN_PUBLIC_FILE_ANALYSIS_RESPONSE,
    }
    result = upload_file(str(mock_file))
    assert result["success"] is True
    assert result["data"] == SCAN_PUBLIC_FILE_ANALYSIS_RESPONSE


@patch("examples.file_and_url_scanning.public_scanning.scan_file.make_api_request")
def test_upload_file_large_success(mock_make_request, mock_file):
    mock_make_request.return_value = {
        "success": True,
        "data": SCAN_PUBLIC_FILE_ANALYSIS_RESPONSE,
    }
    result = upload_file(str(mock_file), "https://upload.url")
    assert result["success"] is True


def test_upload_file_not_found():
    result = upload_file("nonexistent.txt")
    assert result["success"] is False
    assert "File not found" in result["error"]


@patch("examples.file_and_url_scanning.public_scanning.scan_file.make_api_request")
def test_poll_analysis_status_completed(mock_make_request):
    mock_make_request.return_value = {
        "success": True,
        "data": {
            "data": {"attributes": {"status": "completed"}},
            "meta": {"file_info": {"sha256": "test_hash"}},
        },
    }
    result = poll_analysis_status("test_id")
    assert result["success"] is True
    assert result["data"]["data"]["attributes"]["status"] == "completed"


@patch("examples.file_and_url_scanning.public_scanning.scan_file.make_api_request")
def test_poll_analysis_status_error(mock_make_request):
    mock_make_request.return_value = {
        "success": True,
        "data": {"data": {"attributes": {"status": "error"}}},
    }
    result = poll_analysis_status("test_id")
    assert result["success"] is False
    assert "error" in result["error"]


@patch("examples.file_and_url_scanning.public_scanning.scan_file.make_api_request")
@patch("time.sleep")
def test_poll_analysis_status_max_attempts(mock_sleep, mock_make_request):
    mock_make_request.return_value = {
        "success": True,
        "data": {"data": {"attributes": {"status": "queued"}}},
    }
    result = poll_analysis_status("test_id")
    assert result["success"] is False
    assert "Max polling attempts" in result["error"]
    assert mock_sleep.call_count == MAX_POLLING_ATTEMPTS - 1


@patch("examples.file_and_url_scanning.public_scanning.scan_file.make_api_request")
def test_get_file_report_success(mock_make_request):
    mock_make_request.return_value = {
        "success": True,
        "data": SCAN_PUBLIC_FILE_REPORT_RESPONSE,
    }
    result = get_file_report("test_hash")
    assert result["success"] is True
    assert result["data"] == SCAN_PUBLIC_FILE_REPORT_RESPONSE


@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_file_report")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_upload_url")
def test_scan_file_and_get_report_success(
    mock_upload_url, mock_upload, mock_poll, mock_report, mock_file
):
    mock_upload_url.return_value = {
        "success": True,
        "data": {"data": "https://upload.url"},
    }
    mock_upload.return_value = {"success": True, "data": SCAN_PUBLIC_FILE_RESPONSE}
    mock_poll.return_value = {
        "success": True,
        "data": {
            "data": {"attributes": {"status": "completed"}},
            "meta": {"file_info": {"sha256": "test_hash"}},
        },
    }
    mock_report.return_value = {
        "success": True,
        "data": SCAN_PUBLIC_FILE_REPORT_RESPONSE,
    }

    result = scan_file_and_get_report(str(mock_file))
    assert result == SCAN_PUBLIC_FILE_REPORT_RESPONSE


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
def test_scan_file_and_get_report_upload_failure(mock_upload, mock_file):
    mock_upload.return_value = {
        "success": False,
        "error": "Upload failed",
        "should_retry": False,
    }
    result = scan_file_and_get_report(str(mock_file))
    assert result is None


def test_scan_file_and_get_report_file_not_found():
    result = scan_file_and_get_report("nonexistent.txt")
    assert result is None


def test_scan_file_and_get_report_empty_file(tmp_path):
    empty_file = tmp_path / "empty.txt"
    empty_file.touch()
    result = scan_file_and_get_report(str(empty_file))
    assert result is None


def test_print_scan_report_valid(capsys):
    print_scan_report(SCAN_PUBLIC_FILE_REPORT_RESPONSE)
    captured = capsys.readouterr()
    assert "Scan Report" in captured.out
    assert "File SHA-256" in captured.out
    assert "Verdict" in captured.out
    assert "Full JSON Report" in captured.out


def test_print_scan_report_invalid(capsys):
    print_scan_report({})
    captured = capsys.readouterr()
    assert "Invalid or empty scan report" in captured.out


def test_print_scan_report_malicious(capsys):
    malicious_report = {
        "data": {
            "id": "malicious_hash",
            "attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 2}},
        }
    }
    print_scan_report(malicious_report)
    captured = capsys.readouterr()
    assert "MALICIOUS" in captured.out
    assert "Malicious detections: 5" in captured.out


@patch("os.path.getsize")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_upload_url")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_file_report")
def test_large_file_handling(
    mock_report, mock_poll, mock_upload, mock_upload_url, mock_getsize, tmp_path
):
    large_file = tmp_path / "large_file.txt"
    large_file.write_text("A" * (MAX_DIRECT_UPLOAD_SIZE + 1))

    mock_getsize.return_value = MAX_DIRECT_UPLOAD_SIZE + 1
    mock_upload_url.return_value = {
        "success": True,
        "data": {"data": "https://special.upload.url"},
    }
    mock_upload.return_value = {"success": True, "data": SCAN_PUBLIC_FILE_RESPONSE}
    mock_poll.return_value = {
        "success": True,
        "data": {
            "data": {"attributes": {"status": "completed"}},
            "meta": {"file_info": {"sha256": "test_hash"}},
        },
    }
    mock_report.return_value = {
        "success": True,
        "data": SCAN_PUBLIC_FILE_REPORT_RESPONSE,
    }

    result = scan_file_and_get_report(str(large_file))

    mock_upload_url.assert_called_once()

    assert mock_upload.call_count == 1
    args, kwargs = mock_upload.call_args
    assert len(args) >= 2 
    assert args[1] == "https://special.upload.url"
    assert result == SCAN_PUBLIC_FILE_REPORT_RESPONSE


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
def test_upload_retry_logic(mock_upload, mock_file):
    mock_upload.side_effect = [
        {"success": False, "error": "Temp error", "should_retry": True},
        {"success": True, "data": SCAN_PUBLIC_FILE_RESPONSE},
    ]

    with patch(
        "examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status"
    ):
        with patch(
            "examples.file_and_url_scanning.public_scanning.scan_file.get_file_report"
        ):
            result = scan_file_and_get_report(str(mock_file))
            assert result is not None
            assert mock_upload.call_count == 2
