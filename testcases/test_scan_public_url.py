from unittest.mock import patch, MagicMock
from requests.exceptions import Timeout
from typing import Dict

from examples.file_and_url_scanning.public_scanning.scan_url import (
    make_api_request,
    submit_url_for_scanning,
    poll_analysis_status,
    get_url_report,
    scan_url_and_get_report,
    print_scan_report,
    MAX_POLLING_ATTEMPTS,
)
from testcases.constants import (
    SCAN_PUBLIC_URL_RESPONSE,
    SCAN_PUBLIC_URL_ANALYSIS_RESPONSE,
    SCAN_PUBLIC_URL_REPORT_RESPONSE,
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
    assert result["error"] == "Bad request - invalid URL or parameters"
    assert result["should_retry"] is False


@patch("requests.request")
def test_make_api_request_401_error(mock_request):
    mock_request.return_value = mock_error_response(401)
    result = make_api_request("GET", "test_endpoint")
    assert result["success"] is False
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["should_retry"] is False


@patch("requests.request")
def test_make_api_request_timeout(mock_request):
    mock_request.side_effect = Timeout()
    result = make_api_request("GET", "test_endpoint")
    assert result["success"] is False
    assert result["error"] == "Request timed out"
    assert result["should_retry"] is True


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
def test_submit_url_for_scanning_success(mock_make_request):
    mock_make_request.return_value = {"success": True, "data": SCAN_PUBLIC_URL_RESPONSE}
    result = submit_url_for_scanning("https://example.com")
    assert result["success"] is True
    assert result["data"] == SCAN_PUBLIC_URL_RESPONSE

    args, kwargs = mock_make_request.call_args
    assert args[0] == "POST"
    assert args[1] == "urls"
    assert kwargs["data"] == {"url": "https://example.com"}


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
def test_poll_analysis_status_completed(mock_make_request):
    completed_response = {
        "data": {
            "attributes": {"status": "completed"},
        },
        "meta": {
            "url_info": {
                "id": "9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d"
            }
        },
    }

    mock_make_request.return_value = {"success": True, "data": completed_response}

    result = poll_analysis_status("test_analysis_id")

    assert result["success"] is True
    assert (
        result["data"]["url_id"]
        == "9337405ca21d71c5db26b9982aea01707c95a925c8ef99f5a42e7dd29dc06f3d"
    )


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
def test_poll_analysis_status_error(mock_make_request):
    mock_make_request.return_value = {
        "success": True,
        "data": {"data": {"attributes": {"status": "error"}}},
    }
    result = poll_analysis_status("test_analysis_id")
    assert result["success"] is False
    assert "error" in result["error"]


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
@patch("time.sleep")
def test_poll_analysis_status_max_attempts(mock_sleep, mock_make_request):
    mock_make_request.return_value = {
        "success": True,
        "data": {"data": {"attributes": {"status": "queued"}}},
    }
    result = poll_analysis_status("test_analysis_id")
    assert result["success"] is False
    assert "Max polling attempts" in result["error"]
    assert mock_sleep.call_count == MAX_POLLING_ATTEMPTS - 1


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
def test_get_url_report_success(mock_make_request):
    mock_make_request.return_value = {
        "success": True,
        "data": SCAN_PUBLIC_URL_REPORT_RESPONSE,
    }
    result = get_url_report("test_url_id")
    assert result["success"] is True
    assert result["data"] == SCAN_PUBLIC_URL_REPORT_RESPONSE


@patch("examples.file_and_url_scanning.public_scanning.scan_url.get_url_report")
@patch("examples.file_and_url_scanning.public_scanning.scan_url.poll_analysis_status")
@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
)
def test_scan_url_success(mock_submit, mock_poll, mock_report):
    mock_submit.return_value = {"success": True, "data": SCAN_PUBLIC_URL_RESPONSE}
    mock_poll.return_value = {"success": True, "data": {"url_id": "test_url_id"}}
    mock_report.return_value = {
        "success": True,
        "data": SCAN_PUBLIC_URL_REPORT_RESPONSE,
    }

    result = scan_url_and_get_report("https://example.com")
    assert result == SCAN_PUBLIC_URL_REPORT_RESPONSE
    mock_submit.assert_called_once_with("https://example.com")
    mock_poll.assert_called_once_with(SCAN_PUBLIC_URL_RESPONSE["data"]["id"])
    mock_report.assert_called_once_with("test_url_id")


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
)
def test_scan_url_submit_failure(mock_submit):
    mock_submit.return_value = {
        "success": False,
        "error": "Submission failed",
        "should_retry": False,
    }
    result = scan_url_and_get_report("https://example.com")
    assert result is None


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
)
def test_scan_url_submit_retry_success(mock_submit):
    mock_submit.side_effect = [
        {"success": False, "error": "Temp error", "should_retry": True},
        {"success": True, "data": SCAN_PUBLIC_URL_RESPONSE},
    ]

    with patch(
        "examples.file_and_url_scanning.public_scanning.scan_url.poll_analysis_status"
    ):
        with patch(
            "examples.file_and_url_scanning.public_scanning.scan_url.get_url_report"
        ):
            result = scan_url_and_get_report("https://example.com")
            assert result is not None
            assert mock_submit.call_count == 2


def test_print_scan_report_valid(capsys):
    print_scan_report(SCAN_PUBLIC_URL_REPORT_RESPONSE)
    captured = capsys.readouterr()
    assert "URL Scan Report" in captured.out
    assert "Verdict" in captured.out
    assert "Full JSON Report" in captured.out


def test_print_scan_report_invalid(capsys):
    print_scan_report({})
    captured = capsys.readouterr()
    assert "Invalid or empty scan report" in captured.out


def test_print_scan_report_malicious(capsys):
    malicious_report = {
        "data": {
            "attributes": {"last_analysis_stats": {"malicious": 5, "suspicious": 2}}
        }
    }
    print_scan_report(malicious_report)
    captured = capsys.readouterr()
    assert "MALICIOUS" in captured.out
    assert "Malicious detections: 5" in captured.out


def test_scan_url_no_analysis_id():
    with patch(
        "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
    ) as mock_submit:
        mock_submit.return_value = {
            "success": True,
            "data": {"data": {}}, 
        }
        result = scan_url_and_get_report("https://example.com")
        assert result is None


def test_scan_url_polling_no_url_id():
    with patch(
        "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
    ) as mock_submit:
        mock_submit.return_value = {"success": True, "data": SCAN_PUBLIC_URL_RESPONSE}
        with patch(
            "examples.file_and_url_scanning.public_scanning.scan_url.poll_analysis_status"
        ) as mock_poll:
            mock_poll.return_value = {
                "success": True,
                "data": {}, 
            }
            result = scan_url_and_get_report("https://example.com")
            assert result is None
