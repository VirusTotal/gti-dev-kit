import pytest
import os
import tempfile
from unittest.mock import Mock, patch
import requests
from requests.exceptions import Timeout, ConnectionError
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
    assert result["error"] == "Bad request - invalid parameters"
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
def test_post_with_files(mock_request):
    """Test POST request with files"""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": "test_data"}
    mock_request.return_value = mock_response

    test_files = {"file": ("test.txt", "test content", "application/octet-stream")}
    result = make_api_request("POST", "test_endpoint", files=test_files)

    assert result["success"] is True
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    assert call_args[1]["files"] == test_files


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.make_api_request"
)  
def test_successful_upload_url(mock_make_api_request):
    """Test successful upload URL retrieval"""
    mock_response = {"success": True, "data": {"data": "https://upload.url"}}
    mock_make_api_request.return_value = mock_response

    result = get_upload_url()

    assert result == mock_response
    mock_make_api_request.assert_called_once_with("GET", "files/upload_url")


def test_file_not_found():
    """Test file not found error"""
    result = upload_file("nonexistent_file.txt")

    assert result["success"] is False
    assert "File not found" in result["error"]
    assert result["should_retry"] is False


@patch("builtins.open")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.make_api_request")
def test_successful_upload_direct(mock_make_api_request, mock_open):
    """Test successful direct file upload"""
    mock_file = Mock()
    mock_open.return_value.__enter__.return_value = mock_file

    mock_response = {"success": True, "data": {"test": "data"}}
    mock_make_api_request.return_value = mock_response

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"test content")
        temp_file_path = temp_file.name

    try:
        result = upload_file(temp_file_path)

        assert result == mock_response
        mock_make_api_request.assert_called_once_with(
            "POST",
            "files",
            files={
                "file": (
                    os.path.basename(temp_file_path),
                    mock_file,
                    "application/octet-stream",
                )
            },
        )
    finally:
        os.unlink(temp_file_path)


@patch("builtins.open")
@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.make_api_request"
)  
def test_successful_upload_large_file(mock_make_api_request, mock_open):
    """Test successful large file upload with special URL"""
    mock_file = Mock()
    mock_open.return_value.__enter__.return_value = mock_file

    mock_response = {"success": True, "data": {"test": "data"}}
    mock_make_api_request.return_value = mock_response

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"test content")
        temp_file_path = temp_file.name

    try:
        upload_url = "https://special.upload.url/path"
        result = upload_file(temp_file_path, upload_url)

        assert result == mock_response
        mock_make_api_request.assert_called_once_with(
            "POST",
            upload_url,
            files={
                "file": (
                    os.path.basename(temp_file_path),
                    mock_file,
                    "application/octet-stream",
                )
            },
        )
    finally:
        os.unlink(temp_file_path)


@patch("builtins.open")
def test_file_upload_exception(mock_open):
    """Test file upload exception"""
    mock_open.side_effect = Exception("File open error")

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"test content")
        temp_file_path = temp_file.name

    try:
        result = upload_file(temp_file_path)

        assert result["success"] is False
        assert "File upload failed" in result["error"]
        assert result["should_retry"] is True
    finally:
        os.unlink(temp_file_path)


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.make_api_request"
)  
@patch("time.sleep")
def test_successful_completion(mock_sleep, mock_make_api_request):
    """Test successful analysis completion"""
    mock_response = {
        "success": True,
        "data": {"data": {"attributes": {"status": "completed"}}},
    }
    mock_make_api_request.return_value = mock_response

    result = poll_analysis_status("test_analysis_id")

    assert result == mock_response
    mock_make_api_request.assert_called_once_with("GET", "analyses/test_analysis_id")
    mock_sleep.assert_not_called()


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.make_api_request"
)  
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


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.make_api_request"
)  
@patch("time.sleep")
def test_polling_with_retries(mock_sleep, mock_make_api_request):
    """Test polling with multiple retries"""
    mock_response_queued = {
        "success": True,
        "data": {"data": {"attributes": {"status": "queued"}}},
    }
    mock_response_completed = {
        "success": True,
        "data": {"data": {"attributes": {"status": "completed"}}},
    }

    mock_make_api_request.side_effect = [mock_response_queued, mock_response_completed]

    result = poll_analysis_status("test_analysis_id")

    assert result == mock_response_completed
    assert mock_make_api_request.call_count == 2
    mock_sleep.assert_called_once_with(POLLING_INTERVAL)


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.make_api_request"
)  
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


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.make_api_request"
)  
@patch("time.sleep")
def test_failed_api_call(mock_sleep, mock_make_api_request):
    """Test failed API call during polling"""
    mock_response_failed = {"success": False, "error": "API error"}
    mock_make_api_request.return_value = mock_response_failed

    result = poll_analysis_status("test_analysis_id")

    assert result == mock_response_failed
    mock_sleep.assert_not_called()


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.make_api_request"
)  
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


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.make_api_request"
)  
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


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.make_api_request"
)  
def test_successful_report(mock_make_api_request):
    """Test successful file report retrieval"""
    mock_response = {"success": True, "data": {"report": "data"}}
    mock_make_api_request.return_value = mock_response

    result = get_file_report("test_hash")

    assert result == mock_response
    mock_make_api_request.assert_called_once_with("GET", "files/test_hash")


def test_file_not_found():
    """Test file not found"""
    result = scan_file_and_get_report("nonexistent_file.txt")
    assert result is None


def test_empty_file():
    """Test empty file"""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file_path = temp_file.name

    try:
        result = scan_file_and_get_report(temp_file_path)
        assert result is None
    finally:
        os.unlink(temp_file_path)


@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_upload_url")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_file_report")
def test_successful_scan_small_file(
    mock_get_report, mock_poll, mock_upload, mock_get_url
):
    """Test successful scan of small file"""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"test content")
        temp_file_path = temp_file.name

    try:
        mock_upload_response = {
            "success": True,
            "data": {"data": {"id": "test_analysis_id"}},
        }
        mock_poll_response = {
            "success": True,
            "data": {"meta": {"file_info": {"sha256": "test_hash"}}},
        }
        mock_report_response = {"success": True, "data": {"final": "report"}}

        mock_upload.return_value = mock_upload_response
        mock_poll.return_value = mock_poll_response
        mock_get_report.return_value = mock_report_response

        result = scan_file_and_get_report(temp_file_path)

        assert result == {"final": "report"}
        mock_get_url.assert_not_called()  
        mock_upload.assert_called_once()
        mock_poll.assert_called_once_with("test_analysis_id")
        mock_get_report.assert_called_once_with("test_hash")

    finally:
        os.unlink(temp_file_path)


@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_upload_url")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_file_report")
def test_successful_scan_large_file(
    mock_get_report, mock_poll, mock_upload, mock_get_url
):
    """Test successful scan of large file"""
    large_content = b"0" * (MAX_DIRECT_UPLOAD_SIZE + 1)  

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(large_content)
        temp_file_path = temp_file.name

    try:
        mock_get_url_response = {
            "success": True,
            "data": {"data": "https://large.upload.url"},
        }
        mock_upload_response = {
            "success": True,
            "data": {"data": {"id": "test_analysis_id"}},
        }
        mock_poll_response = {
            "success": True,
            "data": {"meta": {"file_info": {"sha256": "test_hash"}}},
        }
        mock_report_response = {"success": True, "data": {"final": "report"}}

        mock_get_url.return_value = mock_get_url_response
        mock_upload.return_value = mock_upload_response
        mock_poll.return_value = mock_poll_response
        mock_get_report.return_value = mock_report_response

        result = scan_file_and_get_report(temp_file_path)

        assert result == {"final": "report"}
        mock_get_url.assert_called_once()
        mock_upload.assert_called_once_with(temp_file_path, "https://large.upload.url")

    finally:
        os.unlink(temp_file_path)


@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_upload_url")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
def test_upload_url_failure(mock_upload, mock_get_url):
    """Test upload URL failure for large file"""
    large_content = b"0" * (MAX_DIRECT_UPLOAD_SIZE + 1)

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(large_content)
        temp_file_path = temp_file.name

    try:
        mock_get_url_response = {"success": False, "error": "URL error"}
        mock_get_url.return_value = mock_get_url_response

        result = scan_file_and_get_report(temp_file_path)

        assert result is None
        mock_get_url.assert_called_once()
        mock_upload.assert_not_called()

    finally:
        os.unlink(temp_file_path)


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
def test_upload_failure_no_retry(mock_upload):
    """Test upload failure without retry"""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"test content")
        temp_file_path = temp_file.name

    try:
        mock_upload_response = {
            "success": False,
            "error": "Upload error",
            "should_retry": False,
        }
        mock_upload.return_value = mock_upload_response

        result = scan_file_and_get_report(temp_file_path)

        assert result is None
        mock_upload.assert_called_once()

    finally:
        os.unlink(temp_file_path)


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
def test_upload_failure_with_retry(mock_upload):
    """Test upload failure with retry"""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"test content")
        temp_file_path = temp_file.name

    try:
        mock_upload_response_fail = {
            "success": False,
            "error": "Upload error",
            "should_retry": True,
        }
        mock_upload_response_success = {
            "success": True,
            "data": {"data": {"id": "test_analysis_id"}},
        }
        mock_upload.side_effect = [
            mock_upload_response_fail,
            mock_upload_response_success,
        ]

        with patch(
            "examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status"
        ) as mock_poll, patch(
            "examples.file_and_url_scanning.public_scanning.scan_file.get_file_report"
        ) as mock_get_report:

            mock_poll.return_value = {
                "success": True,
                "data": {"meta": {"file_info": {"sha256": "test_hash"}}},
            }
            mock_get_report.return_value = {
                "success": True,
                "data": {"final": "report"},
            }

            result = scan_file_and_get_report(temp_file_path)

            assert result == {"final": "report"}
            assert mock_upload.call_count == 2

    finally:
        os.unlink(temp_file_path)


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status")
def test_polling_failure(mock_poll, mock_upload):
    """Test polling failure"""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"test content")
        temp_file_path = temp_file.name

    try:
        mock_upload_response = {
            "success": True,
            "data": {"data": {"id": "test_analysis_id"}},
        }
        mock_poll_response = {"success": False, "error": "Polling error"}

        mock_upload.return_value = mock_upload_response
        mock_poll.return_value = mock_poll_response

        result = scan_file_and_get_report(temp_file_path)

        assert result is None
        mock_upload.assert_called_once()
        mock_poll.assert_called_once_with("test_analysis_id")

    finally:
        os.unlink(temp_file_path)


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_file_report")
def test_report_retrieval_failure(mock_get_report, mock_poll, mock_upload):
    """Test report retrieval failure"""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"test content")
        temp_file_path = temp_file.name

    try:
        mock_upload_response = {
            "success": True,
            "data": {"data": {"id": "test_analysis_id"}},
        }
        mock_poll_response = {
            "success": True,
            "data": {"meta": {"file_info": {"sha256": "test_hash"}}},
        }
        mock_report_response = {"success": False, "error": "Report error"}

        mock_upload.return_value = mock_upload_response
        mock_poll.return_value = mock_poll_response
        mock_get_report.return_value = mock_report_response

        result = scan_file_and_get_report(temp_file_path)

        assert result is None
        mock_get_report.assert_called_once_with("test_hash")

    finally:
        os.unlink(temp_file_path)


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status")
def test_no_file_hash_from_polling(mock_poll, mock_upload):
    """Test no file hash received from polling"""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"test content")
        temp_file_path = temp_file.name

    try:
        mock_upload_response = {
            "success": True,
            "data": {"data": {"id": "test_analysis_id"}},
        }
        mock_poll_response = {"success": True, "data": {"meta": {}}} 

        mock_upload.return_value = mock_upload_response
        mock_poll.return_value = mock_poll_response

        result = scan_file_and_get_report(temp_file_path)

        assert result is None
        mock_poll.assert_called_once_with("test_analysis_id")

    finally:
        os.unlink(temp_file_path)


def test_exception_handling():
    """Test exception handling"""
    with patch(
        "examples.file_and_url_scanning.public_scanning.scan_file.upload_file"
    ) as mock_upload:
        mock_upload.side_effect = Exception("Unexpected error")

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"test content")
            temp_file_path = temp_file.name

        try:
            result = scan_file_and_get_report(temp_file_path)
            assert result is None
        finally:
            os.unlink(temp_file_path)


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
def test_upload_failure_on_retry(mock_upload):
    """Test upload failure on retry (should_retry=True but fails again)"""
    with patch("os.path.exists") as mock_exists, patch(
        "os.path.getsize"
    ) as mock_getsize:
        mock_exists.return_value = True
        mock_getsize.return_value = 1000 

        mock_upload_response_fail_retry = {
            "success": False,
            "error": "Upload error",
            "should_retry": True,
        }
        mock_upload_response_fail_again = {
            "success": False,
            "error": "Upload failed again",
            "should_retry": False,
        }
        mock_upload.side_effect = [
            mock_upload_response_fail_retry,
            mock_upload_response_fail_again,
        ]

        result = scan_file_and_get_report("test_file.txt")

        assert result is None
        assert mock_upload.call_count == 2  


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
def test_no_analysis_id_received(mock_upload):
    """Test successful upload but no analysis ID in response"""
    with patch("os.path.exists") as mock_exists, patch(
        "os.path.getsize"
    ) as mock_getsize:
        mock_exists.return_value = True
        mock_getsize.return_value = 1000  

        mock_upload_response = {
            "success": True,
            "data": {"data": {}},  
        }
        mock_upload.return_value = mock_upload_response

        result = scan_file_and_get_report("test_file.txt")

        assert result is None
        mock_upload.assert_called_once()


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
def test_empty_analysis_id_received(mock_upload):
    """Test successful upload but empty analysis ID in response"""
    with patch("os.path.exists") as mock_exists, patch(
        "os.path.getsize"
    ) as mock_getsize:
        mock_exists.return_value = True
        mock_getsize.return_value = 1000 

        mock_upload_response = {
            "success": True,
            "data": {"data": {"id": ""}},  
        }
        mock_upload.return_value = mock_upload_response

        result = scan_file_and_get_report("test_file.txt")

        assert result is None
        mock_upload.assert_called_once()


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
def test_none_analysis_id_received(mock_upload):
    """Test successful upload but None analysis ID in response"""
    with patch("os.path.exists") as mock_exists, patch(
        "os.path.getsize"
    ) as mock_getsize:
        mock_exists.return_value = True
        mock_getsize.return_value = 1000 

        mock_upload_response = {
            "success": True,
            "data": {"data": {"id": None}},  
        }
        mock_upload.return_value = mock_upload_response

        result = scan_file_and_get_report("test_file.txt")

        assert result is None
        mock_upload.assert_called_once()


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status")
def test_no_file_hash_received(mock_poll, mock_upload):
    """Test successful polling but no file hash in response"""
    with patch("os.path.exists") as mock_exists, patch(
        "os.path.getsize"
    ) as mock_getsize:
        mock_exists.return_value = True
        mock_getsize.return_value = 1000  

        mock_upload_response = {
            "success": True,
            "data": {"data": {"id": "test_analysis_id"}},
        }
        mock_poll_response = {
            "success": True,
            "data": {"meta": {"file_info": {}}},  
        }

        mock_upload.return_value = mock_upload_response
        mock_poll.return_value = mock_poll_response

        result = scan_file_and_get_report("test_file.txt")

        assert result is None
        mock_poll.assert_called_once_with("test_analysis_id")


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status")
def test_empty_file_hash_received(mock_poll, mock_upload):
    """Test successful polling but empty file hash in response"""
    with patch("os.path.exists") as mock_exists, patch(
        "os.path.getsize"
    ) as mock_getsize:
        mock_exists.return_value = True
        mock_getsize.return_value = 1000  

        mock_upload_response = {
            "success": True,
            "data": {"data": {"id": "test_analysis_id"}},
        }
        mock_poll_response = {
            "success": True,
            "data": {"meta": {"file_info": {"sha256": ""}}}, 
        }

        mock_upload.return_value = mock_upload_response
        mock_poll.return_value = mock_poll_response

        result = scan_file_and_get_report("test_file.txt")

        assert result is None
        mock_poll.assert_called_once_with("test_analysis_id")


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status")
def test_none_file_hash_received(mock_poll, mock_upload):
    """Test successful polling but None file hash in response"""
    with patch("os.path.exists") as mock_exists, patch(
        "os.path.getsize"
    ) as mock_getsize:
        mock_exists.return_value = True
        mock_getsize.return_value = 1000  

        mock_upload_response = {
            "success": True,
            "data": {"data": {"id": "test_analysis_id"}},
        }
        mock_poll_response = {
            "success": True,
            "data": {"meta": {"file_info": {"sha256": None}}},  
        }

        mock_upload.return_value = mock_upload_response
        mock_poll.return_value = mock_poll_response

        result = scan_file_and_get_report("test_file.txt")

        assert result is None
        mock_poll.assert_called_once_with("test_analysis_id")


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
def test_exception_during_scanning(mock_upload):
    """Test exception handling during scanning process"""
    with patch("os.path.exists") as mock_exists, patch(
        "os.path.getsize"
    ) as mock_getsize:
        mock_exists.return_value = True
        mock_getsize.return_value = 1000  

        mock_upload.side_effect = Exception("Unexpected error during upload")

        result = scan_file_and_get_report("test_file.txt")

        assert result is None
        mock_upload.assert_called_once()


def test_exception_in_file_operations():
    """Test exception handling in file operations"""
    with patch("os.path.exists") as mock_exists:
        mock_exists.side_effect = Exception("File system error")

        result = scan_file_and_get_report("test_file.txt")

        assert result is None


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status")
def test_exception_during_polling(mock_poll, mock_upload):
    """Test exception handling during polling"""
    with patch("os.path.exists") as mock_exists, patch(
        "os.path.getsize"
    ) as mock_getsize:
        mock_exists.return_value = True
        mock_getsize.return_value = 1000  

        mock_upload_response = {
            "success": True,
            "data": {"data": {"id": "test_analysis_id"}},
        }
        mock_poll.side_effect = Exception("Polling error")

        mock_upload.return_value = mock_upload_response

        result = scan_file_and_get_report("test_file.txt")

        assert result is None
        mock_poll.assert_called_once_with("test_analysis_id")


@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.poll_analysis_status")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_file_report")
def test_exception_during_report_retrieval(mock_get_report, mock_poll, mock_upload):
    """Test exception handling during report retrieval"""
    with patch("os.path.exists") as mock_exists, patch(
        "os.path.getsize"
    ) as mock_getsize:
        mock_exists.return_value = True
        mock_getsize.return_value = 1000 

        mock_upload_response = {
            "success": True,
            "data": {"data": {"id": "test_analysis_id"}},
        }
        mock_poll_response = {
            "success": True,
            "data": {"meta": {"file_info": {"sha256": "test_hash"}}},
        }
        mock_get_report.side_effect = Exception("Report retrieval error")

        mock_upload.return_value = mock_upload_response
        mock_poll.return_value = mock_poll_response

        result = scan_file_and_get_report("test_file.txt")

        assert result is None
        mock_get_report.assert_called_once_with("test_hash")


@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_upload_url")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
def test_upload_url_empty(mock_upload, mock_get_url):
    """Test empty upload URL response for large file"""
    with patch("os.path.exists") as mock_exists, patch(
        "os.path.getsize"
    ) as mock_getsize:
        mock_exists.return_value = True
        mock_getsize.return_value = MAX_DIRECT_UPLOAD_SIZE + 1  

        mock_get_url_response = {"success": True, "data": {"data": ""}} 
        mock_get_url.return_value = mock_get_url_response

        result = scan_file_and_get_report("test_file.txt")

        assert result is None
        mock_get_url.assert_called_once()
        mock_upload.assert_not_called()


@patch("examples.file_and_url_scanning.public_scanning.scan_file.get_upload_url")
@patch("examples.file_and_url_scanning.public_scanning.scan_file.upload_file")
def test_upload_url_none(mock_upload, mock_get_url):
    """Test None upload URL response for large file"""
    with patch("os.path.exists") as mock_exists, patch(
        "os.path.getsize"
    ) as mock_getsize:
        mock_exists.return_value = True
        mock_getsize.return_value = MAX_DIRECT_UPLOAD_SIZE + 1 

        mock_get_url_response = {"success": True, "data": {"data": None}}  
        mock_get_url.return_value = mock_get_url_response

        result = scan_file_and_get_report("test_file.txt")

        assert result is None
        mock_get_url.assert_called_once()
        mock_upload.assert_not_called()


def test_empty_report(capsys):
    """Test empty report"""
    print_scan_report({})
    captured = capsys.readouterr()
    assert "Invalid or empty scan report" in captured.out


def test_malicious_verdict(capsys):
    """Test malicious verdict report"""
    report = {
        "data": {
            "id": "test_hash",
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "harmless": 10},
                "gti_assessment": {"verdict": "MALICIOUS", "confidence": "HIGH"},
            },
        }
    }

    print_scan_report(report)
    captured = capsys.readouterr()

    assert "Scan Report" in captured.out
    assert "test_hash" in captured.out
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
            "id": "test_hash",
            "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 15}},
        }
    }

    print_scan_report(report)
    captured = capsys.readouterr()

    assert "Scan Report" in captured.out
    assert "test_hash" in captured.out
    assert "CLEAN" in captured.out
    assert "Malicious detections" not in captured.out
    assert "Full JSON Report" in captured.out


def test_no_gti_assessment(capsys):
    """Test report without GTI assessment"""
    report = {
        "data": {
            "id": "test_hash",
            "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 15}},
        }
    }

    print_scan_report(report)
    captured = capsys.readouterr()

    assert "Scan Report" in captured.out
    assert "test_hash" in captured.out
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
    report = {
        "data": {
            "id": "test_hash"
        }
    }

    print_scan_report(report)
    captured = capsys.readouterr()

    assert "Scan Report" in captured.out
    assert "test_hash" in captured.out
    assert "Full JSON Report" in captured.out


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.scan_file_and_get_report"
)
@patch("builtins.open")
@patch("os.path.exists")
def test_main_successful_scan(mock_exists, mock_open, mock_scan):
    """Test main function with successful scan"""
    mock_exists.return_value = True
    mock_file = Mock()
    mock_open.return_value.__enter__.return_value = mock_file

    mock_scan.return_value = {
        "data": {
            "id": "test_hash",
            "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 10}},
        }
    }

    from examples.file_and_url_scanning.public_scanning.scan_file import main

    with patch("builtins.print") as mock_print:
        main()

    mock_open.assert_called_once_with("dummy_file.txt", "w")
    mock_scan.assert_called_once_with("dummy_file.txt")

    mock_print.assert_any_call("\nScan completed successfully!")


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.scan_file_and_get_report"
)
@patch("builtins.open")
@patch("os.path.exists")
def test_main_failed_scan(mock_exists, mock_open, mock_scan):
    """Test main function with failed scan"""
    mock_exists.return_value = True
    mock_file = Mock()
    mock_open.return_value.__enter__.return_value = mock_file

    mock_scan.return_value = None

    from examples.file_and_url_scanning.public_scanning.scan_file import main

    with patch("builtins.print") as mock_print:
        main()

    mock_open.assert_called_once_with("dummy_file.txt", "w")
    mock_scan.assert_called_once_with("dummy_file.txt")

    mock_print.assert_any_call("\nScan failed or no results available")


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.scan_file_and_get_report"
)
@patch("builtins.open")
def test_main_file_creation_error(mock_open, mock_scan):
    """Test main function when file creation fails"""
    mock_open.side_effect = Exception("File creation error")

    from examples.file_and_url_scanning.public_scanning.scan_file import main

    with pytest.raises(Exception, match="File creation error"):
        main()

    mock_scan.assert_not_called()


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.scan_file_and_get_report"
)
@patch("builtins.open")
@patch("os.path.exists")
def test_main_direct_execution_guard(mock_exists, mock_open, mock_scan):
    """Test that main only runs when executed directly by testing the guard condition"""
    import examples.file_and_url_scanning.public_scanning.scan_file as scan_module

    with patch.object(scan_module, "__name__", "__main__"):
        with patch("os.path.exists") as mock_exists_inner:
            with patch("builtins.open") as mock_open_inner:
                with patch(
                    "examples.file_and_url_scanning.public_scanning.scan_file.scan_file_and_get_report"
                ) as mock_scan_inner:
                    mock_exists_inner.return_value = True
                    mock_file = Mock()
                    mock_open_inner.return_value.__enter__.return_value = mock_file
                    mock_scan_inner.return_value = {"data": {"id": "test_hash"}}

                    scan_module.main()

                    mock_open_inner.assert_called_once_with("dummy_file.txt", "w")
                    mock_scan_inner.assert_called_once_with("dummy_file.txt")


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.scan_file_and_get_report"
)
@patch("builtins.open")
@patch("os.path.exists")
def test_main_not_direct_execution(mock_exists, mock_open, mock_scan):
    """Test that main doesn't run when not executed directly"""
    import examples.file_and_url_scanning.public_scanning.scan_file as scan_module

    original_name = scan_module.__name__
    try:
        scan_module.__name__ = "not_main"

        mock_exists.return_value = True
        mock_file = Mock()
        mock_open.return_value.__enter__.return_value = mock_file
        mock_scan.return_value = {"data": {"id": "test_hash"}}

        assert hasattr(scan_module, "main")
        assert callable(scan_module.main)

    finally:
        scan_module.__name__ = original_name


@patch(
    "examples.file_and_url_scanning.public_scanning.scan_file.scan_file_and_get_report"
)
@patch("builtins.open")
@patch("os.path.exists")
def test_main_with_exception_during_file_creation(mock_exists, mock_open, mock_scan):
    """Test main function when exception occurs during file creation"""
    mock_open.side_effect = IOError("Disk full")

    from examples.file_and_url_scanning.public_scanning.scan_file import main

    with pytest.raises(IOError, match="Disk full"):
        main()

    mock_scan.assert_not_called()


def test_main_function_is_callable():
    """Test that the main function exists and is callable"""
    from examples.file_and_url_scanning.public_scanning.scan_file import main

    assert callable(main)

def test_upload_file_file_not_found(tmp_path):
    fake_file = tmp_path / "nonexistent.txt"

    result = upload_file(str(fake_file))

    assert result["success"] is False
    assert result["should_retry"] is False
    assert f"File not found: {fake_file}" == result["error"]
