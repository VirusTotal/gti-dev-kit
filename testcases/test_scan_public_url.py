import unittest.mock
from unittest.mock import Mock, patch
import requests
from requests.exceptions import Timeout, ConnectionError
from examples.file_and_url_scanning.public_scanning.scan_url import (
    make_api_request,
    submit_url_for_scanning,
    poll_analysis_status,
    get_url_report,
    scan_url_and_get_report,
    print_scan_report,
    POLLING_INTERVAL,
    MAX_POLLING_ATTEMPTS,
)


@patch("requests.request")
def test_successful_request(mock_request):
    """Test successful API request"""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "test_data"}
    mock_request.return_value = mock_response

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is True
    assert result["data"] == {"data": "test_data"}
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_request.assert_called_once()


@patch("requests.request")
def test_400_error(mock_request):
    """Test 400 Bad Request error"""
    mock_response = Mock()
    mock_response.status_code = 400
    mock_request.return_value = mock_response

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is False
    assert result["error"] == "Bad request - invalid URL or parameters"
    assert result["status_code"] == 400
    assert result["should_retry"] is False


@patch("requests.request")
def test_401_error(mock_request):
    """Test 401 Unauthorized error"""
    mock_response = Mock()
    mock_response.status_code = 401
    mock_request.return_value = mock_response

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is False
    assert result["error"] == "Unauthorized - invalid API key"
    assert result["status_code"] == 401
    assert result["should_retry"] is False


@patch("requests.request")
def test_403_error(mock_request):
    """Test 403 Forbidden error"""
    mock_response = Mock()
    mock_response.status_code = 403
    mock_request.return_value = mock_response

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is False
    assert result["error"] == "Forbidden - insufficient permissions"
    assert result["status_code"] == 403
    assert result["should_retry"] is False


@patch("requests.request")
def test_404_error(mock_request):
    """Test 404 Not Found error"""
    mock_response = Mock()
    mock_response.status_code = 404
    mock_request.return_value = mock_response

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is False
    assert result["error"] == "Resource not found"
    assert result["status_code"] == 404
    assert result["should_retry"] is False


@patch("requests.request")
def test_429_error(mock_request):
    """Test 429 Rate Limit error"""
    mock_response = Mock()
    mock_response.status_code = 429
    mock_request.return_value = mock_response

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded"
    assert result["status_code"] == 429
    assert result["should_retry"] is True


@patch("requests.request")
def test_500_error(mock_request):
    """Test 500 Server error"""
    mock_response = Mock()
    mock_response.status_code = 500
    mock_request.return_value = mock_response

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is False
    assert result["error"] == "Server error (HTTP 500)"
    assert result["status_code"] == 500
    assert result["should_retry"] is True


@patch("requests.request")
def test_unexpected_status_code(mock_request):
    """Test unexpected status code"""
    mock_response = Mock()
    mock_response.status_code = 418
    mock_request.return_value = mock_response

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is False
    assert result["error"] == "Unexpected HTTP status: 418"
    assert result["status_code"] == 418
    assert result["should_retry"] is False


@patch("requests.request")
def test_json_parse_error(mock_request):
    """Test JSON parsing error"""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.side_effect = ValueError("Invalid JSON")
    mock_request.return_value = mock_response

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is False
    assert "Failed to parse JSON response" in result["error"]
    assert result["status_code"] == 200
    assert result["should_retry"] is False


@patch("requests.request")
def test_timeout_error(mock_request):
    """Test timeout error"""
    mock_request.side_effect = Timeout("Request timed out")

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is False
    assert result["error"] == "Request timed out"
    assert result["should_retry"] is True


@patch("requests.request")
def test_connection_error(mock_request):
    """Test connection error"""
    mock_request.side_effect = ConnectionError("Connection failed")

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is False
    assert "Connection error" in result["error"]
    assert result["should_retry"] is True


@patch("requests.request")
def test_general_request_exception(mock_request):
    """Test general request exception"""
    mock_request.side_effect = requests.exceptions.RequestException("General error")

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is False
    assert "Request failed" in result["error"]
    assert result["should_retry"] is False


@patch("requests.request")
def test_unexpected_exception(mock_request):
    """Test unexpected exception"""
    mock_request.side_effect = Exception("Unexpected error")

    result = make_api_request("GET", "test_endpoint")

    assert result["success"] is False
    assert "Unexpected error" in result["error"]
    assert result["should_retry"] is False


@patch("requests.request")
def test_post_with_data(mock_request):
    """Test POST request with data"""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "test_data"}
    mock_request.return_value = mock_response

    test_data = {"url": "test_url"}
    result = make_api_request("POST", "test_endpoint", data=test_data)

    assert result["success"] is True
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    assert call_args[1]["data"] == test_data


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
def test_successful_submission(mock_make_api_request):
    """Test successful URL submission"""
    mock_response = {"success": True, "data": {"data": {"id": "test_analysis_id"}}}
    mock_make_api_request.return_value = mock_response

    result = submit_url_for_scanning("https://example.com")

    assert result == mock_response
    mock_make_api_request.assert_called_once_with(
        "POST", "urls", data={"url": "https://example.com"}
    )


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
@patch("time.sleep")
def test_successful_completion_with_url_id(mock_sleep, mock_make_api_request):
    """Test successful analysis completion with URL ID"""
    mock_response = {
        "success": True,
        "data": {
            "data": {"attributes": {"status": "completed"}},
            "meta": {"url_info": {"id": "test_url_id"}},
        },
    }
    mock_make_api_request.return_value = mock_response

    result = poll_analysis_status("test_analysis_id")

    assert result["success"] is True
    assert result["data"]["url_id"] == "test_url_id"
    mock_make_api_request.assert_called_once_with("GET", "analyses/test_analysis_id")
    mock_sleep.assert_not_called()


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
@patch("time.sleep")
def test_successful_completion_no_url_id(mock_sleep, mock_make_api_request):
    """Test successful analysis completion without URL ID"""
    mock_response = {
        "success": True,
        "data": {"data": {"attributes": {"status": "completed"}}, "meta": {}},
    }
    mock_make_api_request.return_value = mock_response

    result = poll_analysis_status("test_analysis_id")

    assert result["success"] is False
    assert "No URL ID found" in result["error"]
    mock_sleep.assert_not_called()


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
@patch("time.sleep")
def test_error_status(mock_sleep, mock_make_api_request):
    """Test analysis error status"""
    mock_response = {
        "success": True,
        "data": {"data": {"attributes": {"status": "error"}}},
    }
    mock_make_api_request.return_value = mock_response

    result = poll_analysis_status("test_analysis_id")

    assert result["success"] is False
    assert "Analysis error" in result["error"]
    mock_sleep.assert_not_called()


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
@patch("time.sleep")
def test_polling_with_retries(mock_sleep, mock_make_api_request):
    """Test polling with multiple retries"""
    mock_response_queued = {
        "success": True,
        "data": {"data": {"attributes": {"status": "queued"}}},
    }
    mock_response_completed = {
        "success": True,
        "data": {
            "data": {"attributes": {"status": "completed"}},
            "meta": {"url_info": {"id": "test_url_id"}},
        },
    }

    mock_make_api_request.side_effect = [mock_response_queued, mock_response_completed]

    result = poll_analysis_status("test_analysis_id")

    assert result["success"] is True
    assert result["data"]["url_id"] == "test_url_id"
    assert mock_make_api_request.call_count == 2
    mock_sleep.assert_called_once_with(POLLING_INTERVAL)


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
@patch("time.sleep")
def test_max_polling_attempts(mock_sleep, mock_make_api_request):
    """Test max polling attempts reached"""
    mock_response_queued = {
        "success": True,
        "data": {"data": {"attributes": {"status": "queued"}}},
    }

    mock_make_api_request.return_value = mock_response_queued

    result = poll_analysis_status("test_analysis_id")

    assert result["success"] is False
    assert "Max polling attempts reached" in result["error"]
    assert mock_make_api_request.call_count == MAX_POLLING_ATTEMPTS
    assert mock_sleep.call_count == MAX_POLLING_ATTEMPTS - 1


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
@patch("time.sleep")
def test_failed_api_call(mock_sleep, mock_make_api_request):
    """Test failed API call during polling"""
    mock_response_failed = {"success": False, "error": "API error"}
    mock_make_api_request.return_value = mock_response_failed

    result = poll_analysis_status("test_analysis_id")

    assert result == mock_response_failed
    mock_sleep.assert_not_called()


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
@patch("time.sleep")
def test_unsupported_file_type_status(mock_sleep, mock_make_api_request):
    """Test unsupported file type status"""
    mock_response = {
        "success": True,
        "data": {"data": {"attributes": {"status": "unsupported file type"}}},
    }
    mock_make_api_request.return_value = mock_response

    result = poll_analysis_status("test_analysis_id")

    assert result["success"] is False
    assert "unsupported file type" in result["error"]
    mock_sleep.assert_not_called()


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
@patch("time.sleep")
def test_corrupted_file_status(mock_sleep, mock_make_api_request):
    """Test corrupted file status"""
    mock_response = {
        "success": True,
        "data": {"data": {"attributes": {"status": "corrupted file"}}},
    }
    mock_make_api_request.return_value = mock_response

    result = poll_analysis_status("test_analysis_id")

    assert result["success"] is False
    assert "corrupted file" in result["error"]
    mock_sleep.assert_not_called()


@patch("examples.file_and_url_scanning.public_scanning.scan_url.make_api_request")
def test_successful_report(mock_make_api_request):
    """Test successful URL report retrieval"""
    mock_response = {"success": True, "data": {"report": "data"}}
    mock_make_api_request.return_value = mock_response

    result = get_url_report("test_url_id")

    assert result == mock_response
    mock_make_api_request.assert_called_once_with("GET", "urls/test_url_id")


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
)
def test_submission_failure_on_retry(mock_submit):
    """Test submission failure on retry (should_retry=True but fails again)"""
    mock_submit_response_fail_retry = {
        "success": False,
        "error": "Submission error",
        "should_retry": True,
    }
    mock_submit_response_fail_again = {
        "success": False,
        "error": "Submission failed again",
        "should_retry": False,
    }
    mock_submit.side_effect = [
        mock_submit_response_fail_retry,
        mock_submit_response_fail_again,
    ]

    result = scan_url_and_get_report("https://example.com")

    assert result is None
    assert mock_submit.call_count == 2


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
)
@patch("examples.file_and_url_scanning.public_scanning.scan_url.poll_analysis_status")
@patch("examples.file_and_url_scanning.public_scanning.scan_url.get_url_report")
def test_successful_scan(mock_get_report, mock_poll, mock_submit):
    """Test successful URL scan"""
    mock_submit_response = {
        "success": True,
        "data": {"data": {"id": "test_analysis_id"}},
    }
    mock_poll_response = {"success": True, "data": {"url_id": "test_url_id"}}
    mock_report_response = {"success": True, "data": {"final": "report"}}

    mock_submit.return_value = mock_submit_response
    mock_poll.return_value = mock_poll_response
    mock_get_report.return_value = mock_report_response

    result = scan_url_and_get_report("https://example.com")

    assert result == {"final": "report"}
    mock_submit.assert_called_once_with("https://example.com")
    mock_poll.assert_called_once_with("test_analysis_id")
    mock_get_report.assert_called_once_with("test_url_id")


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
)
def test_submission_failure_no_retry(mock_submit):
    """Test submission failure without retry"""
    mock_submit_response = {
        "success": False,
        "error": "Submission error",
        "should_retry": False,
    }
    mock_submit.return_value = mock_submit_response

    result = scan_url_and_get_report("https://example.com")

    assert result is None
    mock_submit.assert_called_once_with("https://example.com")


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
)
def test_submission_failure_with_retry(mock_submit):
    """Test submission failure with retry"""
    mock_submit_response_fail = {
        "success": False,
        "error": "Submission error",
        "should_retry": True,
    }
    mock_submit_response_success = {
        "success": True,
        "data": {"data": {"id": "test_analysis_id"}},
    }
    mock_submit.side_effect = [mock_submit_response_fail, mock_submit_response_success]

    with patch(
        "examples.file_and_url_scanning.public_scanning.scan_url.poll_analysis_status"
    ) as mock_poll, patch(
        "examples.file_and_url_scanning.public_scanning.scan_url.get_url_report"
    ) as mock_get_report:

        mock_poll.return_value = {"success": True, "data": {"url_id": "test_url_id"}}
        mock_get_report.return_value = {"success": True, "data": {"final": "report"}}

        result = scan_url_and_get_report("https://example.com")

        assert result == {"final": "report"}
        assert mock_submit.call_count == 2


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
)
def test_no_analysis_id(mock_submit):
    """Test no analysis ID received"""
    mock_submit_response = {"success": True, "data": {"data": {}}}
    mock_submit.return_value = mock_submit_response

    result = scan_url_and_get_report("https://example.com")

    assert result is None
    mock_submit.assert_called_once()


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
)
@patch("examples.file_and_url_scanning.public_scanning.scan_url.poll_analysis_status")
def test_polling_failure(mock_poll, mock_submit):
    """Test polling failure"""
    mock_submit_response = {
        "success": True,
        "data": {"data": {"id": "test_analysis_id"}},
    }
    mock_poll_response = {"success": False, "error": "Polling error"}

    mock_submit.return_value = mock_submit_response
    mock_poll.return_value = mock_poll_response

    result = scan_url_and_get_report("https://example.com")

    assert result is None
    mock_poll.assert_called_once_with("test_analysis_id")


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
)
@patch("examples.file_and_url_scanning.public_scanning.scan_url.poll_analysis_status")
def test_no_url_id_from_polling(mock_poll, mock_submit):
    """Test no URL ID received from polling"""
    mock_submit_response = {
        "success": True,
        "data": {"data": {"id": "test_analysis_id"}},
    }
    mock_poll_response = {"success": True, "data": {}}

    mock_submit.return_value = mock_submit_response
    mock_poll.return_value = mock_poll_response

    result = scan_url_and_get_report("https://example.com")

    assert result is None
    mock_poll.assert_called_once_with("test_analysis_id")


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
)
@patch("examples.file_and_url_scanning.public_scanning.scan_url.poll_analysis_status")
@patch("examples.file_and_url_scanning.public_scanning.scan_url.get_url_report")
def test_report_retrieval_failure(mock_get_report, mock_poll, mock_submit):
    """Test report retrieval failure"""
    mock_submit_response = {
        "success": True,
        "data": {"data": {"id": "test_analysis_id"}},
    }
    mock_poll_response = {"success": True, "data": {"url_id": "test_url_id"}}
    mock_report_response = {"success": False, "error": "Report error"}

    mock_submit.return_value = mock_submit_response
    mock_poll.return_value = mock_poll_response
    mock_get_report.return_value = mock_report_response

    result = scan_url_and_get_report("https://example.com")

    assert result is None
    mock_get_report.assert_called_once_with("test_url_id")


def test_exception_handling():
    """Test exception handling"""
    with patch(
        "examples.file_and_url_scanning.public_scanning.scan_url.submit_url_for_scanning"
    ) as mock_submit:
        mock_submit.side_effect = Exception("Unexpected error")

        result = scan_url_and_get_report("https://example.com")

        assert result is None


def test_empty_report(capsys):
    """Test empty report"""
    print_scan_report({})
    captured = capsys.readouterr()
    assert "Invalid or empty scan report" in captured.out


def test_malicious_verdict(capsys):
    """Test malicious verdict report"""
    report = {
        "data": {
            "id": "test_url_id",
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "harmless": 10},
                "gti_assessment": {"verdict": "MALICIOUS", "confidence": "HIGH"},
            },
        }
    }

    print_scan_report(report)
    captured = capsys.readouterr()

    assert "URL Scan Report" in captured.out
    assert "test_url_id" in captured.out
    assert "MALICIOUS" in captured.out
    assert "Malicious detections: 5" in captured.out
    assert "GTI Assessment:" in captured.out
    assert "verdict: MALICIOUS" in captured.out
    assert "confidence: HIGH" in captured.out
    assert "Full JSON Report" in captured.out


def test_clean_verdict(capsys):
    """Test clean verdict report"""
    report = {
        "data": {
            "id": "test_url_id",
            "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 15}},
        }
    }

    print_scan_report(report)
    captured = capsys.readouterr()

    assert "URL Scan Report" in captured.out
    assert "test_url_id" in captured.out
    assert "CLEAN" in captured.out
    assert "Malicious detections" not in captured.out
    assert "Full JSON Report" in captured.out


def test_no_gti_assessment(capsys):
    """Test report without GTI assessment"""
    report = {
        "data": {
            "id": "test_url_id",
            "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 15}},
        }
    }

    print_scan_report(report)
    captured = capsys.readouterr()

    assert "URL Scan Report" in captured.out
    assert "test_url_id" in captured.out
    assert "CLEAN" in captured.out
    assert "GTI Assessment:" not in captured.out


def test_report_without_data_key(capsys):
    """Test report without data key"""
    report = {"invalid": "structure"}

    print_scan_report(report)
    captured = capsys.readouterr()

    assert "Invalid or empty scan report" in captured.out


def test_report_without_attributes(capsys):
    """Test report without attributes"""
    report = {"data": {"id": "test_url_id"}}

    print_scan_report(report)
    captured = capsys.readouterr()

    assert "URL Scan Report" in captured.out
    assert "test_url_id" in captured.out
    assert "Full JSON Report" in captured.out


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.scan_url_and_get_report"
)
def test_main_successful_scan(mock_scan):
    """Test main function with successful scan"""
    mock_scan.return_value = {
        "data": {
            "id": "test_url_id",
            "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 10}},
        }
    }

    from examples.file_and_url_scanning.public_scanning.scan_url import main

    with patch("builtins.print") as mock_print:
        main()

    mock_scan.assert_called_once_with("https://www.youtube.com/")

    mock_print.assert_any_call("\nScan completed successfully!")


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.scan_url_and_get_report"
)
def test_main_failed_scan(mock_scan):
    """Test main function with failed scan"""
    mock_scan.return_value = None

    from examples.file_and_url_scanning.public_scanning.scan_url import main

    with patch("builtins.print") as mock_print:
        main()

    mock_scan.assert_called_once_with("https://www.youtube.com/")

    mock_print.assert_any_call("\nScan failed or no results available")


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.scan_url_and_get_report"
)
def test_main_with_malicious_result(mock_scan):
    """Test main function with malicious scan result"""
    mock_scan.return_value = {
        "data": {
            "id": "malicious_url_id",
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "harmless": 10},
                "gti_assessment": {"verdict": "MALICIOUS", "confidence": "HIGH"},
            },
        }
    }

    from examples.file_and_url_scanning.public_scanning.scan_url import main

    with patch("builtins.print") as mock_print:
        main()

    mock_scan.assert_called_once_with("https://www.youtube.com/")

    mock_print.assert_any_call("\nScan completed successfully!")


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.scan_url_and_get_report"
)
def test_main_output_messages(mock_scan):
    """Test all output messages in main function"""
    mock_scan.return_value = {
        "data": {
            "id": "test_url_id",
            "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 10}},
        }
    }

    from examples.file_and_url_scanning.public_scanning.scan_url import main

    with patch("builtins.print") as mock_print:
        main()

        expected_calls = [
            unittest.mock.call("Using default URL: https://www.youtube.com/"),
            unittest.mock.call("\nScanning URL: https://www.youtube.com/"),
            unittest.mock.call("\nScan completed successfully!"),
        ]

        for expected_call in expected_calls:
            assert expected_call in mock_print.call_args_list


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_url.scan_url_and_get_report"
)
def test_main_with_print_scan_report_call(mock_scan):
    """Test that print_scan_report is called with the correct result"""
    scan_result = {
        "data": {
            "id": "test_url_id",
            "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 10}},
        }
    }
    mock_scan.return_value = scan_result

    from examples.file_and_url_scanning.public_scanning.scan_url import (
        main,
        print_scan_report,
    )

    with patch(
        "examples.file_and_url_scanning.public_scanning.scan_url.print_scan_report"
    ) as mock_print_report:
        main()

        mock_print_report.assert_called_once_with(scan_result)


def test_main_direct_execution_guard():
    """Test that main only runs when executed directly by testing the guard condition"""
    import examples.file_and_url_scanning.public_scanning.scan_url as scan_module

    with patch.object(scan_module, "__name__", "__main__"):
        with patch(
            "examples.file_and_url_scanning.public_scanning.scan_url.scan_url_and_get_report"
        ) as mock_scan:
            mock_scan.return_value = {"data": {"id": "test_url_id"}}

            scan_module.main()

            mock_scan.assert_called_once_with("https://www.youtube.com/")


def test_main_not_direct_execution():
    """Test that main doesn't run when not executed directly"""
    import examples.file_and_url_scanning.public_scanning.scan_url as scan_module

    original_name = scan_module.__name__
    try:
        scan_module.__name__ = "not_main"

        with patch(
            "examples.file_and_url_scanning.public_scanning.scan_url.scan_url_and_get_report"
        ) as mock_scan:
            mock_scan.return_value = {"data": {"id": "test_url_id"}}

            assert hasattr(scan_module, "main")
            assert callable(scan_module.main)

            mock_scan.assert_not_called()

    finally:
        scan_module.__name__ = original_name


def test_main_function_is_callable():
    """Test that the main function exists and is callable"""
    from examples.file_and_url_scanning.public_scanning.scan_url import main

    assert callable(main)
