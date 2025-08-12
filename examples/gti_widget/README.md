# Google Threat Intelligence (GTI) Widget Embedding Script

This repository contains a Python script designed to interface with the Google Threat Intelligence (GTI) API to retrieve VirusTotal Augment Widget URLs for observables such as IPs, domains, URLs, or file hashes. The script enables security analysts, threat researchers, and developers to embed interactive, live visualizations of threat intelligence data into their platforms, facilitating quick assessment of Indicators of Compromise (IOCs) and their relationships.

## Overview

The `widget.py` script streamlines the retrieval of VirusTotal Augment Widget URLs, which provide a rich, curated view of an IOC’s threat context, including detection ratios, relationships, and metadata. The widget is rendered in an iframe served by VirusTotal, requiring no complex parsing or custom templates, and can be customized to match your platform’s theme. This script supports threat intelligence workflows by enabling seamless integration of GTI data into IOC enrichment panels, incident investigation views, or dedicated threat intelligence pages.


## GTI Widget Embedding
  - **Objective**: Embed GTI widgets as part of threat intelligence workflows to provide rich, curated information on IOCs in a clear, visual format.

  - **Key Implementation Points**:
      - Identify key use cases where a GTI widget can be leveraged, such as in IOC enrichment panels, incident investigation views, or dedicated threat intelligence pages.
      - Implement the generation and fetching of the GTI widget according to official GTI recommendations, ensuring proper authentication and responsive rendering.
      - Ensure the widget is embedded using an iframe to display VirusTotal’s live, interactive threat context, including relationships, detection data, and threat graphs.

  - **Relevant API Calls**:
      - `/widget/url`: Fetches the embed-ready URL for the VirusTotal Augment Widget for a specified observable (e.g., IP, domain, URL, or file hash).

  - **User Experience (UX) Best Practice**:
      - Consider GTI widget configuration options to adjust the widget’s appearance (e.g., colors, theme) to match your platform’s look and feel, ensuring a seamless integration.

  - **Configuration Tip**:
      - Allow an administrator to enable or disable widget embedding globally to manage UI performance and visual complexity. Configure retry logic for transient API failures to ensure reliable widget retrieval.

  - [**Best Practices Guide**](https://docs.google.com/document/d/1foYWa5FnlwtYBIo63YIZU5AOInI7UsNdrn9g0ty25Ag/edit?resourcekey=0-SIeMz9ALACxg0qGd75Jm4g&tab=t.0#heading=h.iu05rh2fex9i)

## Key Features
  - **Widget URL Retrieval**: Fetches embed-ready URLs for VirusTotal Augment Widgets, enabling quick integration into third-party platforms.

  - **Detection Summary**: Displays detection counts from reputable antivirus engines, providing a clear indicator of an IOC’s threat level.

  - **Error Handling**: Implements robust error detection and reporting, including retries for rate limits and network issues, with detailed status feedback.

  - **Threat Visualization**: Embeds interactive widgets with threat graphs and contextual data (e.g., relationships, submission metadata, static properties), suitable for both junior and senior analysts.

  - **Customizable Rendering**: Supports customization of widget appearance to align with your platform’s theme, using VirusTotal’s configuration options.

  - **Bring-Your-Own-API-Key Model**: Uses your GTI API key for authentication, ensuring compliance and simplicity without requiring complex API parsing.


## Scripts Overview
The repository includes the following script, tailored to retrieve and display VirusTotal Augment Widget URLs for threat intelligence visualization.

#### `widget.py`
  - **Purpose**: Retrieves a VirusTotal Augment Widget URL for a given observable (IP, domain, URL, or file hash) using the GTI API, displaying the widget URL and detection ratio.

  - **Key Features**:
      - **Widget URL Retrieval**: Fetches the embed-ready URL for the VT Augment widget.
      - **Detection Summary**: Displays detection count from reputable AV engines.
      - **Error Handling**: Provides detailed status feedback and retry suggestions for transient failures (e.g., rate limits, server errors).

  - **API Endpoints Used**:
      - `/widget/url`: Fetches the embeddable widget URL for a specified observable.

  - **Use Case**: Embedding interactive threat intelligence visualizations in security platforms for IOC enrichment, incident investigation, or threat analysis.


## How to Run the Script
Follow these steps to set up and run the script:

### 1.  Install Dependencies
Ensure you have the required Python libraries installed. Run the following command in your terminal or command prompt:

```bash
pip install -r requirements.txt
```

### 2.  Configure API Credentials
The script requires a valid GTI API key and product header. Replace the placeholders in `widget.py`:

```python
GTI_API_KEY = "YOUR_API_KEY"
X_TOOL_HEADER = "YOUR_PRODUCT_NAME"
```

### 3.  Run the Script
Execute the script using Python from the command line. Navigate to the `gti_widget` directory and run:

```bash
python widget.py
```

### 4.  Customize Inputs
Modify the default observable in `widget.py` (e.g., `observable = "1.1.1.1"`) to target a different IP, domain, URL, or file hash. Refer to inline comments for guidance on required parameters and formats.

### 5.  Review Output
The script generates a widget URL and detection ratio for the specified observable. SExample outputs are available in the `/gti_widget` directory. For instance, the output of the `widget.py` script can be found in the `widget_output.md` file.

## Additional Notes
  - **Widget URL Validity**: Widget URLs are ephemeral and valid for 3 days. Plan to refresh them periodically for continuous use in your platform.

  - **API Quota Management**: The script includes retry logic for HTTP 429 (rate limit) and 5xx errors. Monitor API usage to stay within your quota, especially for frequent requests.

  - **Error Handling**: The script handles network failures, invalid responses, and authentication errors, providing clear feedback and retry suggestions. Check console output for details.

  - **Output Storage**: By default, outputs are printed to the console. Modify `widget.py` to save the widget URL or detection data to a file for integration with other systems.

  - **Script Documentation**: The `widget.py` script contains detailed comments explaining its functionality, parameters, and error handling.

  - **GTI API Documentation**: For endpoint details and query syntax, refer to the official [GTI Documentation](https://docs.virustotal.com/reference/widgeturl).

  - **Troubleshooting**: Create a `docs/troubleshooting.md` file for common issues like API errors, rate limits, or invalid observables, or refer to console output for error details.

  - **Widget Customization**: Use VirusTotal’s widget configuration options (e.g., `bd1`, `bg1`, `bg2`, `fg1` for colors) to match your platform’s theme, as shown in the widget URL parameters.
