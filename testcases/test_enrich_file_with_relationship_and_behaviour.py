import pytest
import os
import json
import requests
from unittest.mock import patch, mock_open, MagicMock
from examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour import (
    get_relationship_cache_file,
    get_cache_filename,
    make_api_request,
    get_file_relationships,
    get_mitre_data,
    get_file_behaviours,
    print_relationships,
    print_mitre_data,
    print_sandbox_behaviours,
    main,
    CACHE_DIR,
    BASE_URL,
    PARAMS,
)
from testcases.constants import (
    RELATIONSHIP_FILE_HASH,
    ENRICH_FILE_RELATIONSHIPS_RESPONSE,
    ENRICH_FILE_MITRE_RESPONSE,
    ENRICH_FILE_SANDBOX_RESPONSE,
)

MOCK_RELATIONSHIPS_CACHE_FILE = os.path.join(
    CACHE_DIR, f"file_{RELATIONSHIP_FILE_HASH}_relationships_cache.json"
)
MOCK_MITRE_CACHE_FILE = os.path.join(
    CACHE_DIR, f"file_{RELATIONSHIP_FILE_HASH}_mitre_data_cache.json"
)
MOCK_SANDBOX_CACHE_FILE = os.path.join(
    CACHE_DIR, f"file_{RELATIONSHIP_FILE_HASH}_sandbox_behaviours_cache.json"
)


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


def test_get_relationship_cache_file():
    """Test cache filename generation for relationships."""
    expected = os.path.join(
        CACHE_DIR, f"file_{RELATIONSHIP_FILE_HASH}_relationships_cache.json"
    )
    result = get_relationship_cache_file(RELATIONSHIP_FILE_HASH)
    assert result == expected, f"Expected cache filename {expected}, got {result}"


def test_get_cache_filename():
    """Test cache filename generation for MITRE and sandbox data."""
    expected = os.path.join(
        CACHE_DIR, f"file_{RELATIONSHIP_FILE_HASH}_mitre_data_cache.json"
    )
    result = get_cache_filename(RELATIONSHIP_FILE_HASH, "mitre_data")
    assert result == expected, f"Expected cache filename {expected}, got {result}"


def test_make_api_request_success(mock_requests_get):
    """Test successful API request."""
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_FILE_RELATIONSHIPS_RESPONSE
    mock_requests_get.return_value = mock_response

    result = make_api_request(
        f"{BASE_URL}/files/{RELATIONSHIP_FILE_HASH}", params=PARAMS
    )

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_RELATIONSHIPS_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_requests_get.assert_called_once_with(
        f"{BASE_URL}/files/{RELATIONSHIP_FILE_HASH}",
        headers={"x-apikey": "YOUR_API_KEY", "x-tool": "YOUR_PRODUCT_NAME"},
        params=PARAMS,
        timeout=60,
    )


def test_make_api_request_400_bad_request(mock_requests_get):
    """Test API request with 400 Bad Request."""
    mock_response = MagicMock(status_code=400)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/files/{RELATIONSHIP_FILE_HASH}")

    assert result["success"] is False
    assert result["error"] == "Bad request - invalid file hash or parameters."
    assert result["status_code"] == 400
    assert result["should_retry"] is False


def test_make_api_request_401_unauthorized(mock_requests_get):
    """Test API request with 401 Unauthorized."""
    mock_response = MagicMock(status_code=401)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/files/{RELATIONSHIP_FILE_HASH}")

    assert result["success"] is False
    assert result["error"] == "Unauthorized - check your API key."
    assert result["status_code"] == 401
    assert result["should_retry"] is False


def test_make_api_request_403_forbidden(mock_requests_get):
    """Test API request with 403 Forbidden."""
    mock_response = MagicMock(status_code=403)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/files/{RELATIONSHIP_FILE_HASH}")

    assert result["success"] is False
    assert result["error"] == "Forbidden - insufficient permissions."
    assert result["status_code"] == 403
    assert result["should_retry"] is False


def test_make_api_request_404_not_found(mock_requests_get):
    """Test API request with 404 Not Found."""
    mock_response = MagicMock(status_code=404)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/files/{RELATIONSHIP_FILE_HASH}")

    assert result["success"] is False
    assert result["error"] == "File hash not found."
    assert result["status_code"] == 404
    assert result["should_retry"] is False


def test_make_api_request_429_rate_limit(mock_requests_get):
    """Test API request with 429 Rate Limit Exceeded."""
    mock_response = MagicMock(status_code=429)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/files/{RELATIONSHIP_FILE_HASH}")

    assert result["success"] is False
    assert result["error"] == "Rate limit exceeded."
    assert result["status_code"] == 429
    assert result["should_retry"] is True


def test_make_api_request_500_server_error(mock_requests_get):
    """Test API request with 500 Server Error."""
    mock_response = MagicMock(status_code=500)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/files/{RELATIONSHIP_FILE_HASH}")

    assert result["success"] is False
    assert result["error"] == "Server error 500."
    assert result["status_code"] == 500
    assert result["should_retry"] is True


def test_make_api_request_unexpected_http_status(mock_requests_get):
    """Test API request with 500 Server Error."""
    mock_response = MagicMock(status_code=900)
    mock_requests_get.return_value = mock_response

    result = make_api_request(f"{BASE_URL}/files/{RELATIONSHIP_FILE_HASH}")

    assert result["success"] is False
    assert result["error"] == "Unexpected status code: 900."
    assert result["status_code"] == 900
    assert result["should_retry"] is False


def test_make_api_request_timeout(mock_requests_get):
    """Test API request with timeout."""
    mock_requests_get.side_effect = requests.exceptions.Timeout

    result = make_api_request(f"{BASE_URL}/files/{RELATIONSHIP_FILE_HASH}")

    assert result["success"] is False
    assert result["error"] == "Request timed out."
    assert result["should_retry"] is True


def test_make_api_request_connection_error(mock_requests_get):
    """Test API request with connection error."""
    mock_requests_get.side_effect = requests.exceptions.ConnectionError

    result = make_api_request(f"{BASE_URL}/files/{RELATIONSHIP_FILE_HASH}")

    assert result["success"] is False
    assert result["error"] == "Connection error. Check your internet connection."
    assert result["should_retry"] is True


def test_make_api_request_unexpected_error(mock_requests_get):
    """Test API request with unexpected error."""
    mock_requests_get.side_effect = requests.exceptions.RequestException(
        "Unexpected error"
    )

    result = make_api_request(f"{BASE_URL}/files/{RELATIONSHIP_FILE_HASH}")

    assert result["success"] is False
    assert result["error"] == "Unexpected error: Unexpected error"
    assert result["should_retry"] is False


def test_get_file_relationships_from_cache(mock_os_path_exists, mock_open_file):
    """Test fetching relationship data from cache."""
    mock_os_path_exists.return_value = True
    mock_open_file().read.return_value = json.dumps(ENRICH_FILE_RELATIONSHIPS_RESPONSE)

    result = get_file_relationships(RELATIONSHIP_FILE_HASH)

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_RELATIONSHIPS_RESPONSE
    mock_open_file.assert_called_with(MOCK_RELATIONSHIPS_CACHE_FILE, "r")


def test_get_file_relationships_cache_io_error(
    mock_os_path_exists, mock_open_file, mock_requests_get
):
    """Test cache read error, falling back to API for relationships."""
    mock_os_path_exists.return_value = True
    mock_open_file.side_effect = IOError("Cannot read file")
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_FILE_RELATIONSHIPS_RESPONSE
    mock_requests_get.return_value = mock_response

    result = get_file_relationships(RELATIONSHIP_FILE_HASH)

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_RELATIONSHIPS_RESPONSE
    mock_requests_get.assert_called_once()


def test_get_file_relationships_no_cache_api_success(
    mock_os_path_exists,
    mock_requests_get,
    mock_open_file,
    mock_os_makedirs,
    mock_json_dump,
):
    """Test fetching relationship data from API with successful cache save."""
    mock_os_path_exists.return_value = False
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_FILE_RELATIONSHIPS_RESPONSE
    mock_requests_get.return_value = mock_response

    result = get_file_relationships(RELATIONSHIP_FILE_HASH)

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_RELATIONSHIPS_RESPONSE
    mock_os_makedirs.assert_called_with(CACHE_DIR, exist_ok=True)
    mock_open_file.assert_called_with(MOCK_RELATIONSHIPS_CACHE_FILE, "w")
    mock_json_dump.assert_called_once_with(
        ENRICH_FILE_RELATIONSHIPS_RESPONSE, mock_open_file(), indent=2
    )


def test_get_file_relationships_no_cache_cache_write_error(
    mock_os_path_exists, mock_requests_get, mock_open_file, mock_os_makedirs
):
    """Test API success but cache write failure for relationships."""
    mock_os_path_exists.return_value = False
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_FILE_RELATIONSHIPS_RESPONSE
    mock_requests_get.return_value = mock_response
    mock_open_file.side_effect = IOError("Cannot write file")

    result = get_file_relationships(RELATIONSHIP_FILE_HASH)

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_RELATIONSHIPS_RESPONSE
    mock_os_makedirs.assert_called_with(CACHE_DIR, exist_ok=True)
    mock_open_file.assert_called_with(MOCK_RELATIONSHIPS_CACHE_FILE, "w")


def test_get_mitre_data_from_cache(mock_os_path_exists, mock_open_file):
    """Test fetching MITRE data from cache."""
    mock_os_path_exists.return_value = True
    mock_open_file().read.return_value = json.dumps(ENRICH_FILE_MITRE_RESPONSE)

    result = get_mitre_data(RELATIONSHIP_FILE_HASH)

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_MITRE_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_open_file.assert_called_with(MOCK_MITRE_CACHE_FILE, "r")


def test_get_mitre_data_cache_io_error(
    mock_os_path_exists, mock_open_file, mock_requests_get
):
    """Test cache read error, falling back to API for MITRE data."""
    mock_os_path_exists.return_value = True
    mock_open_file.side_effect = IOError("Cannot read file")
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_FILE_MITRE_RESPONSE
    mock_requests_get.return_value = mock_response

    result = get_mitre_data(RELATIONSHIP_FILE_HASH)

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_MITRE_RESPONSE
    mock_requests_get.assert_called_once()


def test_get_mitre_data_no_cache_api_success(
    mock_os_path_exists,
    mock_requests_get,
    mock_open_file,
    mock_os_makedirs,
    mock_json_dump,
):
    """Test fetching MITRE data from API with successful cache save."""
    mock_os_path_exists.return_value = False
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_FILE_MITRE_RESPONSE
    mock_requests_get.return_value = mock_response

    result = get_mitre_data(RELATIONSHIP_FILE_HASH)

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_MITRE_RESPONSE
    mock_os_makedirs.assert_called_with(CACHE_DIR, exist_ok=True)
    mock_open_file.assert_called_with(MOCK_MITRE_CACHE_FILE, "w")
    mock_json_dump.assert_called_once_with(
        ENRICH_FILE_MITRE_RESPONSE, mock_open_file(), indent=2
    )


def test_get_mitre_data_no_cache_cache_write_error(
    mock_os_path_exists, mock_requests_get, mock_open_file, mock_os_makedirs
):
    """Test API success but cache write failure for MITRE data."""
    mock_os_path_exists.return_value = False
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_FILE_MITRE_RESPONSE
    mock_requests_get.return_value = mock_response
    mock_open_file.side_effect = IOError("Cannot write file")

    result = get_mitre_data(RELATIONSHIP_FILE_HASH)

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_MITRE_RESPONSE
    mock_os_makedirs.assert_called_with(CACHE_DIR, exist_ok=True)
    mock_open_file.assert_called_with(MOCK_MITRE_CACHE_FILE, "w")


def test_get_file_behaviours_from_cache(mock_os_path_exists, mock_open_file):
    """Test fetching sandbox behaviors from cache."""
    mock_os_path_exists.return_value = True
    mock_open_file().read.return_value = json.dumps(ENRICH_FILE_SANDBOX_RESPONSE)

    result = get_file_behaviours(RELATIONSHIP_FILE_HASH)

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_SANDBOX_RESPONSE
    assert result["error"] is None
    assert result["status_code"] == 200
    assert result["should_retry"] is False
    mock_open_file.assert_called_with(MOCK_SANDBOX_CACHE_FILE, "r")


def test_get_file_behaviours_cache_io_error(
    mock_os_path_exists, mock_open_file, mock_requests_get
):
    """Test cache read error, falling back to API for sandbox behaviors."""
    mock_os_path_exists.return_value = True
    mock_open_file.side_effect = IOError("Cannot read file")
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_FILE_SANDBOX_RESPONSE
    mock_requests_get.return_value = mock_response

    result = get_file_behaviours(RELATIONSHIP_FILE_HASH)

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_SANDBOX_RESPONSE
    mock_requests_get.assert_called_once()


def test_get_file_behaviours_no_cache_api_success(
    mock_os_path_exists,
    mock_requests_get,
    mock_open_file,
    mock_os_makedirs,
    mock_json_dump,
):
    """Test fetching sandbox behaviors from API with successful cache save."""
    mock_os_path_exists.return_value = False
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_FILE_SANDBOX_RESPONSE
    mock_requests_get.return_value = mock_response

    result = get_file_behaviours(RELATIONSHIP_FILE_HASH)

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_SANDBOX_RESPONSE
    mock_os_makedirs.assert_called_with(CACHE_DIR, exist_ok=True)
    mock_open_file.assert_called_with(MOCK_SANDBOX_CACHE_FILE, "w")
    mock_json_dump.assert_called_once_with(
        ENRICH_FILE_SANDBOX_RESPONSE, mock_open_file(), indent=2
    )


def test_get_file_behaviours_no_cache_cache_write_error(
    mock_os_path_exists, mock_requests_get, mock_open_file, mock_os_makedirs
):
    """Test API success but cache write failure for sandbox behaviors."""
    mock_os_path_exists.return_value = False
    mock_response = MagicMock(status_code=200)
    mock_response.json.return_value = ENRICH_FILE_SANDBOX_RESPONSE
    mock_requests_get.return_value = mock_response
    mock_open_file.side_effect = IOError("Cannot write file")

    result = get_file_behaviours(RELATIONSHIP_FILE_HASH)

    assert result["success"] is True
    assert result["data"] == ENRICH_FILE_SANDBOX_RESPONSE
    mock_os_makedirs.assert_called_with(CACHE_DIR, exist_ok=True)
    mock_open_file.assert_called_with(MOCK_SANDBOX_CACHE_FILE, "w")


def test_print_relationships_success(capsys):
    """Test printing a successful relationship response."""
    print_relationships(
        {"success": True, "data": ENRICH_FILE_RELATIONSHIPS_RESPONSE},
        RELATIONSHIP_FILE_HASH,
    )
    captured = capsys.readouterr()

    assert (
        f"Relationship Summary for File Hash: {RELATIONSHIP_FILE_HASH}" in captured.out
    )
    assert "> Malware Families:" in captured.out
    assert "- No related entities found." in captured.out
    assert "> Comments:" in captured.out
    assert f"- ID: f-{RELATIONSHIP_FILE_HASH}-0834142e | Type: comment" in captured.out
    assert "> Related Threat Actors:" in captured.out


def test_print_relationships_failed_request(capsys):
    """Test printing a failed relationship response."""
    response = {"success": False, "error": "API error"}
    print_relationships(response, RELATIONSHIP_FILE_HASH)
    captured = capsys.readouterr()

    assert "API error" in captured.out


def test_print_relationships_no_relationships(capsys):
    """Test printing a response with no relationships."""
    response = {"success": True, "data": {"data": {}}}
    print_relationships(response, RELATIONSHIP_FILE_HASH)
    captured = capsys.readouterr()

    assert (
        f"No relationships found for file hash: {RELATIONSHIP_FILE_HASH}"
        in captured.out
    )


def test_mitre_data_with_no_tactics(capsys):
    mitre_data = {"success": True, "data": {"data": {"sandbox1": {"tactics": []}}}}
    result = print_mitre_data(mitre_data, "hash123")
    captured = capsys.readouterr()

    assert result
    assert "No tactics found for this sandbox." in captured.out


def test_mitre_data_with_tactic_no_techniques(capsys):
    mitre_data = {
        "success": True,
        "data": {
            "data": {
                "sandbox1": {
                    "tactics": [
                        {"name": "Persistence", "id": "TA0003", "techniques": []}
                    ]
                }
            }
        },
    }
    result = print_mitre_data(mitre_data, "hash123")
    captured = capsys.readouterr()

    assert result
    assert "Tactic: Persistence (TA0003)" in captured.out
    assert "No techniques found for this tactic." in captured.out


def test_sandbox_behaviours_no_command_executions(capsys):
    behaviours_result = {
        "success": True,
        "data": {
            "data": [
                {
                    "id": "beh1",
                    "attributes": {
                        "sandbox_name": "sandboxA",
                        "command_executions": [],
                    },
                }
            ]
        },
    }
    print_sandbox_behaviours(behaviours_result, "hash123")
    captured = capsys.readouterr()

    assert "Sandbox Name: sandboxA" in captured.out
    assert "Behavior ID: beh1" in captured.out
    assert "No command executions found." in captured.out


def test_main_relationships_retry(monkeypatch, capsys):
    calls = {"count": 0}

    def fake_get_file_relationships(fh):
        if calls["count"] == 0:
            calls["count"] += 1
            return {"success": False, "should_retry": True}
        return {"success": True}

    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.get_file_relationships",
        fake_get_file_relationships,
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.print_relationships",
        lambda data, fh: print("print_relationships RETRY"),
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.get_mitre_data",
        lambda fh: {"success": True},
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.print_mitre_data",
        lambda data, fh: None,
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.get_file_behaviours",
        lambda fh: {"success": True},
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.print_sandbox_behaviours",
        lambda data, fh: None,
    )

    main()
    out = capsys.readouterr().out
    assert "Retrying failed request..." in out
    assert "print_relationships RETRY" in out


def test_main_mitre_retry(monkeypatch, capsys):
    calls = {"count": 0}

    def fake_get_mitre_data(fh):
        if calls["count"] == 0:
            calls["count"] += 1
            return {"success": False, "should_retry": True}
        return {"success": True}

    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.get_file_relationships",
        lambda fh: {"success": True},
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.print_relationships",
        lambda data, fh: None,
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.get_mitre_data",
        fake_get_mitre_data,
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.print_mitre_data",
        lambda data, fh: print("print_mitre_data RETRY"),
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.get_file_behaviours",
        lambda fh: {"success": True},
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.print_sandbox_behaviours",
        lambda data, fh: None,
    )

    main()
    out = capsys.readouterr().out
    assert "Retrying failed request..." in out
    assert "print_mitre_data RETRY" in out


def test_main_behaviours_retry(monkeypatch, capsys):
    calls = {"count": 0}

    def fake_get_file_behaviours(fh):
        if calls["count"] == 0:
            calls["count"] += 1
            return {"success": False, "should_retry": True}
        return {"success": True}

    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.get_file_relationships",
        lambda fh: {"success": True},
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.print_relationships",
        lambda data, fh: None,
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.get_mitre_data",
        lambda fh: {"success": True},
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.print_mitre_data",
        lambda data, fh: None,
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.get_file_behaviours",
        fake_get_file_behaviours,
    )
    monkeypatch.setattr(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.print_sandbox_behaviours",
        lambda data, fh: print("print_sandbox_behaviours RETRY"),
    )

    main()
    out = capsys.readouterr().out
    assert "Retrying failed request..." in out
    assert "print_sandbox_behaviours RETRY" in out


def test_print_relationships_empty_relationships(capsys):
    """Test printing a response with empty relationships."""
    response = {"success": True, "data": {"data": {"relationships": {}}}}
    print_relationships(response, RELATIONSHIP_FILE_HASH)
    captured = capsys.readouterr()

    assert (
        f"No relationships found for file hash: {RELATIONSHIP_FILE_HASH}"
        in captured.out
    )


def test_print_mitre_data_success(capsys):
    """Test printing successful MITRE data."""
    result = print_mitre_data(
        {"success": True, "data": ENRICH_FILE_MITRE_RESPONSE}, RELATIONSHIP_FILE_HASH
    )
    captured = capsys.readouterr()

    assert result is True
    assert f"MITRE ATT&CK Data for File {RELATIONSHIP_FILE_HASH}" in captured.out
    assert "Sandbox Name: C2AE" in captured.out
    assert "- Tactic: Persistence (TA0003)" in captured.out
    assert "- Technique: Registry Run Keys / Startup Folder (T1547.001)" in captured.out
    assert "- Technique: Scheduled Task/Job (T1053)" in captured.out
    assert "- Tactic: Defense Evasion (TA0005)" in captured.out
    assert "- Technique: Obfuscated Files or Information (T1027)" in captured.out


def test_print_mitre_data_failed_request(capsys):
    """Test printing failed MITRE data request."""
    result = print_mitre_data(
        {"success": False, "error": "API error", "should_retry": True},
        RELATIONSHIP_FILE_HASH,
    )
    captured = capsys.readouterr()

    assert result is False
    assert (
        f"Error fetching MITRE data for {RELATIONSHIP_FILE_HASH}: API error"
        in captured.out
    )
    assert "Note: This request might succeed if retried later." in captured.out


def test_print_mitre_data_no_data(capsys):
    """Test printing MITRE data with no data."""
    result = print_mitre_data({"success": True, "data": {}}, RELATIONSHIP_FILE_HASH)
    captured = capsys.readouterr()

    assert result is False
    assert f"No MITRE data found for file {RELATIONSHIP_FILE_HASH}." in captured.out


def test_print_mitre_data_processing_error(capsys):
    """Test printing MITRE data with processing error."""
    result = print_mitre_data({"success": True, "data": None}, RELATIONSHIP_FILE_HASH)
    captured = capsys.readouterr()

    assert result is False
    assert "Error processing MITRE data" in captured.out


def test_print_sandbox_behaviours_success(capsys):
    """Test printing successful sandbox behaviors."""
    print_sandbox_behaviours(
        {"success": True, "data": ENRICH_FILE_SANDBOX_RESPONSE}, RELATIONSHIP_FILE_HASH
    )
    captured = capsys.readouterr()

    assert (
        f"Sandbox Behavior Analysis for File {RELATIONSHIP_FILE_HASH}" in captured.out
    )
    assert "Sandbox Name: C2AE" in captured.out
    assert "- Command: cmd.exe /c echo malicious > file.txt" in captured.out
    assert "- Command: net user add malicious_user" in captured.out
    assert "Sandbox Name: Zenbox" in captured.out
    assert "- Command: powershell.exe -exec bypass" in captured.out


def test_print_sandbox_behaviours_failed_request(capsys):
    """Test printing failed sandbox behaviors request."""
    print_sandbox_behaviours(
        {"success": False, "error": "API error"}, RELATIONSHIP_FILE_HASH
    )
    captured = capsys.readouterr()

    assert (
        f"Sandbox Behavior Analysis for File {RELATIONSHIP_FILE_HASH}" in captured.out
    )
    assert "Error retrieving sandbox behaviors: API error" in captured.out


def test_print_sandbox_behaviours_no_data(capsys):
    """Test printing sandbox behaviors with no data."""
    print_sandbox_behaviours({"success": True, "data": {}}, RELATIONSHIP_FILE_HASH)
    captured = capsys.readouterr()

    assert (
        f"Sandbox Behavior Analysis for File {RELATIONSHIP_FILE_HASH}" in captured.out
    )
    assert "No sandbox behavior data found." in captured.out


def test_main_retry_logic(mock_os_path_exists, mock_requests_get, capsys):
    """Test main function retry logic for failed requests."""
    mock_os_path_exists.return_value = False
    mock_response_fail = MagicMock(status_code=429)
    mock_response_success = MagicMock(status_code=200)
    mock_response_success.json.side_effect = [
        ENRICH_FILE_RELATIONSHIPS_RESPONSE,
        ENRICH_FILE_MITRE_RESPONSE,
        ENRICH_FILE_SANDBOX_RESPONSE,
    ]
    mock_requests_get.side_effect = [
        mock_response_fail,
        mock_response_success,
        mock_response_success,
        mock_response_success,
    ]

    with patch(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.get_file_relationships"
    ) as mock_get_file_relationships, patch(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.get_mitre_data"
    ) as mock_get_mitre_data, patch(
        "examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour.get_file_behaviours"
    ) as mock_get_file_behaviours:
        mock_get_file_relationships.side_effect = [
            {"success": False, "error": "Rate limit exceeded.", "should_retry": True},
            {"success": True, "data": ENRICH_FILE_RELATIONSHIPS_RESPONSE},
        ]
        mock_get_mitre_data.return_value = {
            "success": True,
            "data": ENRICH_FILE_MITRE_RESPONSE,
        }
        mock_get_file_behaviours.return_value = {
            "success": True,
            "data": ENRICH_FILE_SANDBOX_RESPONSE,
        }
        from examples.automatic_and_manual_enrichment.enrich_file_with_relationship_and_behaviour import (
            main,
        )

        main()

    captured = capsys.readouterr()
    assert "Retrying failed request..." in captured.out
    assert (
        f"Relationship Summary for File Hash: {RELATIONSHIP_FILE_HASH}" in captured.out
    )
    assert f"MITRE ATT&CK Data for File {RELATIONSHIP_FILE_HASH}" in captured.out
    assert (
        f"Sandbox Behavior Analysis for File {RELATIONSHIP_FILE_HASH}" in captured.out
    )
