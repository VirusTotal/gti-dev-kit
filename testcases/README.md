# GTI Dev Kit Testcases README

This repository contains test cases for the Google Threat Intelligence (GTI) Dev Kit, designed to validate the functionality of scripts located in various example directories. These test cases ensure the reliability and accuracy of enrichment scripts for different data types, including their relationship and behavior analysis features, alongside ingestion, polling, processing, scanning, information retrieval, and intelligence gathering capabilities. The tests utilize the `pytest` framework and mock objects to simulate API requests and file operations.

## Overview

The GTI Dev Kit provides a set of Python scripts to enrich threat intelligence data by querying the GTI API. The test cases cover a range of scripts across multiple functionalities, each designed to handle different aspects of threat intelligence processing.

## Test Structure

### Common Fixtures
- `mock_requests_get`: Mocks the `requests.get` function to simulate API responses.
- `mock_os_path_exists`: Mocks `os.path.exists` to control cache file existence checks.
- `mock_open_file`: Mocks file operations using `mock_open`.
- `mock_os_makedirs`: Mocks directory creation with `os.makedirs`.
- `mock_json_dump`: Mocks JSON data serialization with `json.dump`.
- `mock_time_sleep`: Mocks `time.sleep` for polling tests.
- `mock_datetime`: Mocks `datetime` for time-based tests.
- `mock_requests`: Mocks `requests.request` for broader request handling.

### Test Cases by Script

#### `test_enrich_domain.py`
- **Tests**: Cache filename generation, successful API request, error handling, cache operations, report printing with/without data, invalid data, exceptions, and main retry logic.
- **Focus**: Validates domain enrichment and report output.

#### `test_enrich_ip.py`
- **Tests**: Cache filename generation, successful API request, error handling, cache operations, report printing with/without data, invalid data, processing errors, and main retry logic.
- **Focus**: Verifies IP address enrichment and reporting.

#### `test_enrich_domain_with_relationship.py`
- **Tests**: Relationship cache filename generation, successful API request, cache operations, relationship printing with/without data, failed requests, empty relationships, and main retry logic.
- **Focus**: Ensures domain relationship enrichment.

#### `test_enrich_url_with_relationship.py`
- **Tests**: Cache filename generation, successful API request, cache operations, relationship printing with/without data, failed requests, empty relationships, and main retry logic.
- **Focus**: Validates URL relationship enrichment.

#### `test_enrich_file.py`
- **Tests**: Cache filename generation, successful API request, error handling, cache operations, report printing with/without data, invalid data, processing errors, and main retry logic.
- **Focus**: Confirms file enrichment and reporting.

#### `test_enrich_url.py`
- **Tests**: Cache filename generation, successful API request, error handling, cache operations, report printing for various statuses, invalid data, processing errors, and main retry logic.
- **Focus**: Ensures URL enrichment and reporting.

#### `test_enrich_ip_with_relationship.py`
- **Tests**: Relationship cache filename generation, successful API request, cache operations, relationship printing with/without data, failed requests, empty relationships, and main retry logic.
- **Focus**: Verifies IP relationship enrichment.

#### `test_enrich_file_with_relationship_and_behaviour.py`
- **Tests**: Relationship/behavior cache filename generation, successful API requests, cache operations, relationship printing, additional data printing, and main retry logic.
- **Focus**: Validates file relationship and behavior enrichment.

#### `test_ingest_asm_issues.py`
- **Tests**: Successful API request, error handling, cache operations, result printing with/without data, failed requests, formatting errors, and main retry logic.
- **Focus**: Validates issue ingestion.

#### `test_ingest_asm_issues_with_polling.py`
- **Tests**: Successful API request, error handling, cache operations, result printing, polling with data/no data, and main function with polling.
- **Focus**: Ensures issue polling functionality.

#### `test_ingest_dtm_alerts.py`
- **Tests**: Successful API request, error handling, cache operations, result printing with/without data, main with/without results, and main with retry logic.
- **Focus**: Verifies alert ingestion.

#### `test_ingest_dtm_alerts_with_polling.py`
- **Tests**: Successful API request, error handling, cache operations, result printing, page token parsing, polling with data/no data, main with/without results, and main with retry logic.
- **Focus**: Ensures alert polling functionality.

#### `test_ingest_ioc_stream.py`
- **Tests**: Successful API request with/without params, error handling, cache operations, stream printing with/without data, exceptions, and main with/without retry logic.
- **Focus**: Validates stream ingestion.

#### `test_ingest_ioc_stream_with_polling.py`
- **Tests**: Successful API request with/without cursor, error handling, cache operations, stream printing with data/no data/errors, and main with polling.
- **Focus**: Ensures stream polling functionality.

#### `test_ingest_threat_list.py`
- **Tests**: Successful API request, error handling, cache operations, list printing with/without data, additional list printing, exceptions, and main with/without retry logic.
- **Focus**: Verifies list ingestion.

#### `test_ingest_threat_list_with_polling.py`
- **Tests**: Successful API request, error handling, cache operations, list printing, polling with data/all failures, exceptions, and main with polling.
- **Focus**: Ensures list polling functionality.

#### `test_scan_private_url.py`
- **Tests**: Successful API request, error handling, timeout/connection errors, submission/poll/report retrieval, report printing, main with success/failure/direct execution guard, and function callability.
- **Focus**: Validates private URL scanning.

#### `test_scan_public_file.py`
- **Tests**: Successful API request, error handling, timeout/connection errors, upload URL retrieval, file upload, poll/report retrieval, report printing, main with success/failure/exceptions/direct execution guard, and function callability.
- **Focus**: Verifies public file scanning.

#### `test_scan_private_file.py`
- **Tests**: Successful API request, error handling, timeout/connection errors, upload URL retrieval, file upload, poll/report retrieval, report printing, main with success/failure, and file not found handling.
- **Focus**: Validates private file scanning.

#### `test_scan_public_url.py`
- **Tests**: Successful API request, error handling, timeout/connection errors, submission/poll/report retrieval, report printing, main with success/failure/direct execution guard, and function callability.
- **Focus**: Verifies public URL scanning.

#### `test_widget.py`
- **Tests**: Successful widget request, error handling, cache operations, info printing with/without data, and main with success/failure.
- **Focus**: Ensures information retrieval.

#### `test_vulnerability.py`
- **Tests**: Successful API request, error handling, cache operations, vulnerability printing with/without data, and main with success/no data/missing attributes.
- **Focus**: Validates intelligence gathering.

## Prerequisites

- **Python**: Version 3.6 or higher.
- **Dependencies**: Install required packages using `pip install pytest requests unittest-mock`.

## Running Tests

1. Navigate to the directory containing the test files.
2. Run the tests using the following command:
```bash
pytest -v
```