# **Google Threat Intelligence (GTI) Example Integration Scripts**

Google Threat Intelligence (GTI) unifies crowdsourced intelligence from VirusTotal and curated intelligence from Mandiant with Google's infrastructure to deliver unparalleled threat visibility. This repository is a curated collection of Python scripts and workflows designed to help you build capable and functional integrations with the GTI API. Each module includes detailed descriptions, examples, and sample responses to get you started.

## **Overview**

The scripts in this repository are designed to be modular and easy to use, providing a clear path for integrating GTI's capabilities. Each script includes robust error handling and generates structured JSON outputs, making them simple to integrate into your existing security platforms. The primary goal is to reduce manual work, speed up response times, and provide a unified view of your threat landscape.

### **Where to Start**

A typical integration journey begins with **manual IOC enrichment**, using scripts to look up indicators like IPs, domains, and file hashes. This can evolve into **automated enrichment** that typically leveraged in integrations with SIEM’s, and from there, expand to ingesting higher-level intelligence objects for a more comprehensive threat picture and further use cases depending on the implemented scenario. Each example section this repo provides may contain an extra README with additional information. For further reading, please refer to the [GTI API documentation portal](https://gtidocs.virustotal.com/reference/api-overview).

For building compatible Google TI integrations, this README **contains important information on requirements for integrations and an FAQ**. 

All API requests **must include the x-tool header to identify the integration**, following the **org.productName.majorversion.minorversion format**, see below on the x-tool and other headers.

### **Covered Use Cases**

This repository covers the following key use cases:

* **IOC Enrichment**: Manually or automatically enrich indicators of compromise to gain immediate context during investigations.  
* **File and URL Scanning**: Submit suspicious files and URLs for in-depth static and dynamic analysis.  
* **Curated Threat List & IOC Stream Ingestion**: Pull curated threat lists and real-time IOC streams to feed watchlists and detection rules.  
* **Vulnerability Intelligence**: Retrieve detailed information on CVEs, including risk ratings and associated threat actor activity, to prioritize patching.  
* **Attack Surface Management (ASM)**: Ingest ASM issues to identify misconfigurations and exposures.  
* **Digital Threat Monitoring (DTM)**: Ingest DTM alerts to track external threats like phishing campaigns.  
* **Workflow Automation Guidance**: Provides general guidance and examples on how to build automated playbooks in SOAR platforms.  
* **Interactive Visualization**: Embed the GTI Widget to provide analysts with rich, interactive threat context directly within your security platforms.

## **Repository Structure**

The repository is organized into the following main directories:

* /docs: Contains additional docs and guidance materials for working with the GTI API, and a Postman collection of a sample requests for enrichment, files scanning and other use cases referenced in this repo.    
* /example: Contains all the core scripts and workflows, categorized by function. Note that subdirectories may contain their own README.md files with more detailed instructions on the related functionality.  
* /testcases: Pytest files for validating script functionality.  
* requirements.txt: A list of required Python dependencies.

## **Best Practices and Usage Guidelines**

* **API Key Security**: Always use environment variables or a secrets management system (like Google Secret Manager or HashiCorp Vault) to protect your GTI API key. Never embed it in client-side code.  
* **Quota Management**: Be mindful of your API quota. You can programmatically check your remaining quota by making a GET request to the /users/{apikey}/overall\_quotas endpoint. Adjust polling intervals in scripts to balance data freshness with API usage.  
* **Efficient Data Fetching**:  
  * To reduce the size of API responses for IOCs, use the exclude\_attributes query parameter to filter out unnecessary fields.  
  * Collection-based endpoints have a limit of 40 objects per call. To work around this, consider using the /intelligence/search endpoint, which has a higher pagination limit of 300 objects.  
* **Fetching Related Objects**: To get related entities for an object (e.g., malware families for a file), first request the relationship *descriptors* using the relationships query parameter. Then, make a second API call to the specific relationship endpoint (e.g., /files/{hash}/malware\_families) to get the full details. **Note: fetching relationships can consume large amounts of API quota**, it is recommended to monitor the quota usage when fetching the relationships and provide an option to limit the relationships requested.  
* **Testing**: Always test scripts in a non-production environment before deploying them.

## **Getting Started**

Follow these steps to get the scripts up and running.

### **1\. Prerequisites**

* Python 3.8 or higher.  
* A valid GTI API key, [this article](https://gtidocs.virustotal.com/docs/google-threat-intelligence-api-keys) explains where to get the key.

### **2\. Installation**

Clone the repository and install the required packages:

git clone \[https://github.com/your-repo/gti-integration-scripts.git\](https://github.com/your-repo/gti-integration-scripts.git)  
cd gti-integration-scripts  
pip install \-r requirements.txt

### **3\. Configuration**

In each script you intend to use, configure your GTI API key and a product header.

GTI\_API\_KEY \= "YOUR\_API\_KEY"  
X\_TOOL\_HEADER \= "YOUR\_PRODUCT\_NAME"

**Note: The X\_TOOL\_HEADER is required for tracking integration usage**, it should follow a org.productName.majorversion.minorversion format.

### **4\. Running a Script**

Navigate to the script's directory and run it using Python. For detailed instructions, refer to the README.md file within each module's directory.

cd example/ASM  
python ingest\_asm\_issues.py

Each module also includes a markdown file with an example of the script's output (e.g., ingest\_asm\_issues\_output.md).

## **GTI API Reference**

| Use Case | Script | Primary API Endpoint(s) |
| :---- | :---- | :---- |
| Domain Enrichment | enrich\_domain.py | GET /api/v3/domains/{domain} |
| File Enrichment | enrich\_file.py | GET /api/v3/files/{file\_hash} |
| IP Enrichment | enrich\_ip.py | GET /api/v3/ip\_address/{ip\_address} |
| URL Enrichment | enrich\_url.py | GET /api/v3/urls/{url\_id} |
| ASM Ingestion | ingest\_asm\_issues.py | GET /api/v3/asm/search/issues/{search\_string} |
| DTM Ingestion | ingest\_dtm\_alerts.py | GET /api/v3/dtm/alerts |
| IOC Stream Ingestion | ingest\_ioc\_stream.py | GET /api/v3/ioc\_stream |
| Threat List Ingestion | ingest\_threat\_list.py | GET /api/v3/threat\_lists/{category}/latest |
| Private File Scanning | private\_scanning/scan\_file.py | POST /api/v3/private/files, GET /api/v3/private/analyses/{analysis\_id} |
| Private URL Scanning | private\_scanning/scan\_url.py | POST /api/v3/private/urls, GET /api/v3/private/analyses/{analysis\_id} |
| Public File Scanning | public\_scanning/scan\_file.py | POST /api/v3/files, GET /api/v3/analyses/{analysis\_id} |
| Public URL Scanning | public\_scanning/scan\_url.py | POST /api/v3/urls, GET /api/v3/analyses/{analysis\_id} |
| GTI Widget | widget.py | GET /gtiwidget?query={ioc} |
| Vulnerability Intelligence | vulnerability.py | GET /collections |

## **Integration Development Requirements** 

To support and streamline the Google TI integration development by Partners, this section contains requirements Partners should follow while working on integrations.

* Google  will require Partner to set up a specific header as a user-agent  (“x-tool”) under the API request to the Google API identifying the Partner Technology.   The x-tool should be the product organization, product name and version, ie x-tool: org.productName.v1.0

* Partner should only use the Google standard, publicly available API to develop, configure, and set up its Product for the purpose of building an integration for the mutual customer of both parties.

* Partner shall prepare a user interface (UI), acceptable to Google, for the mutual customer to enter their Google Intelligence API keys.  Prior to release of the intelligence connector, Partner agrees to  demonstrate the intel connector and use cases with Google Intel and Google product management to ensure alignment on branding, mapping of data fields and Google API outputs.

* Partner shall prepare a demonstration of the integration for Google Intel tech alliances product team to validate the use cases, branding, and implementation,  Partner shall not release this integration until approved to do so.


* Partner shall provide a point of contact for their support team for us to refer customers to for the integration connector.


* GTI Development keys are not to be use for customer demonstrations.  If that is required the partner will need to go through the Google Partner NFR process. 

* No AI / ML usage of GTI Intelligence is allowed unless explicit approval for the use case is sought and approved.

* To enhance security and ensure compliance, access to the Global Threat Intelligence (GTI) APIs is now strictly governed by individual API keys, with all authentication managed directly by GTI. This ensures that each customer's access is uniquely identifiable and billed accurately, as charges are incurred on a per-call basis. Consequently, any system or service that integrates with the GTI APIs must ensure that the end-user's API key is used for every request, and authentication is not proxied or handled by downstream systems.  
    
* This policy of direct, user-specific authentication is coupled with stringent data usage and storage requirements. All data retrieved through a customer's API key is for that customer's exclusive use and must be stored in a separate, dedicated data store. The sharing of this data with any other user or entity is explicitly prohibited. This measure is in place to uphold the integrity of the licensing and billing model, which is predicated on individual API call consumption. By mandating isolated data storage, it prevents the unauthorized redistribution or commingling of data, ensuring that each customer is accountable for their own API usage and the associated costs.

## **Integration Development FAQs**

### **Q: Where are the public GTI docs located?** 

**A:**  [https://gtidocs.virustotal.com/](https://gtidocs.virustotal.com/) 

---

### **Q: What is the suggested order of integrations?**

**A:** Most customers initially focus on **IoC (Indicator of Compromise) enrichment**. This provides immediate value by allowing them to get more context on suspicious files, URLs, domains, and IP addresses. After that, a common integration path is to incorporate **Threat Lists** and **IoC Streams** to proactively block threats and stay updated on emerging campaigns.

Then it is recommended that you tackle the higher level objects (Actor, Malware, Campaigns and Reports), as well as integrating with the Threat Profile. 

---

### **Q: How can I use my existing VT integration to quickly build a GTI enrichment integration?**

**A:** You can leverage the same API and simply amend the header to include your ‘x-tool’ name. Then, update your integration to surface the data in the new ‘gti\_assessments’ section of the API response.

---

### **Q: How can I determine the remaining API Quota my customer has?**

**A:** You can programmatically check the remaining [API quota](https://gtidocs.virustotal.com/reference/get-user-overall-quotas) by making a GET request to the `/users/{apikey}/overall_quotas` endpoint. This will return a JSON object detailing the hourly, daily, and monthly API request allowances and the number of requests used.

Alternatively, a user can view their current quota usage in the VirusTotal GUI by navigating to their API key page: [https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey).

---

### **Q: How can I determine which Threat Lists a customer has access to?**

**A:** To see the threat lists a customer is [subscribed](https://gtidocs.virustotal.com/reference/list-provisioned-threat-lists) to, you can make a GET request to the `/v3/threat_lists` endpoint, with the users x-api key. This will return a list of the threat intelligence feeds the user can access.

---

### **Q: Which API serves the threat lists?**

**A:** The Threat Lists are served via the `/threat_lists/{threat_list_id}/iocs` endpoint. You would first get the list of available `threat_list_id`s from the user's subscriptions and then use this endpoint to retrieve the Indicators of Compromise from a specific list.

---

### **Q: How do I configure my system to consume IoC Streams, and how do I filter by origin?**

**A:** The IoC Stream provides a near real-time feed of indicators. You can access it via this [API](https://gtidocs.virustotal.com/reference/get-objects-from-the-ioc-stream)  `/ioc_stream` . The documentation points to the "IoC Stream" view, which centralizes notifications from your active Livehunt (YARA rules) notifications, subscribed collections, and threat actors. You can filter the notifications by various criteria, including the `source`. For example, you can filter by a specific Livehunt ruleset name or a collection name to consume only the IoCs from that origin.

---

### **Q: How do I perform enrichments on an IoC? Provide an example of an IP address.**

**A:** To enrich an IoC, you make a GET request to the appropriate endpoint for that indicator type. For an IP address, the endpoint is `/ip_addresses/{ip}`.

Here's an example of how to enrich the IP address `8.8.8.8`:

**Request:**

```
GET /api/v3/ip_addresses/8.8.8.8
Host: www.virustotal.com
x-apikey: <Your API Key>
```

**Response:** The API will return a JSON object containing detailed information about the IP address, including reputation, resolutions, related samples, and more.

---

### **Q: Known limitations of the API?**

**A:** Currently, you can only get a maximum of **40 objects per API call** for collection-based endpoints. Additionally, the public API has a default rate limit of **4 requests per minute**. Private API keys have higher rate limits.

---

### **Q: How do I get related entities to an object through the API?**

**A:** When retrieving a specific object, such as a file, you can discover its related entities by using the `relationships` query parameter. This initial request will return a list of "descriptors" for each related object, which includes its unique ID and type.

For example, to get the malware families and related threat actors for a specific file hash, your API call would look like this:

Request for descriptors:

```
GET /api/v3/files/8cc57bc1284f68b2aae1e6cb8fa86793db131e9bbbfb40b5eb235a0628c57da9?relationships=malware_families,related_threat_actors
Host: www.virustotal.com
x-apikey: <Your API Key>
```

To obtain the full, detailed information for those related entities, you must then make additional API calls to the specific relationship endpoints. For example, to get the full details for the malware families related to the file, you would make the following call:

Request for full relationship details:

```
GET /api/v3/files/8cc57bc1284f68b2aae1e6cb8fa86793db131e9bbbfb40b5eb235a0628c57da9/malware_families
Host: www.virustotal.com
x-apikey: <Your API Key>
```

---

### **Q: How do I download yara rules associated with a malware family?** 

**A**:  you can get the ruleset for a family by doing:

You can do is check any malware family / tool with the following query:  
curl \--request GET \\  
     \--url [https://www.virustotal.com/api/v3/collections/\[COLLECTION\_ID\]/hunting\_rulesets](https://www.virustotal.com/api/v3/collections/[COLLECTION_ID]/hunting_rulesets) \\  
     \--header 'accept: application/json' \\  
     \--header 'x-apikey: xxx'  
this will return the curated rules

 you can use this to specifically get Toolkits:  
You can do with the following endpoint: [https://gtidocs.virustotal.com/reference/intelligence-search](https://gtidocs.virustotal.com/reference/intelligence-search)

and the following modifier: "entity:collection collection\_type:software-toolkit"

that would be an example: curl \--request GET \\  
     \--url '[https://www.virustotal.com/api/v3/intelligence/search?query=entity%3Acollection%20collection\_type%3Asoftware-toolkit](https://www.virustotal.com/api/v3/intelligence/search?query=entity%3Acollection%20collection_type%3Asoftware-toolkit)' \\  
     \--header 'accept: application/json' \\  
     \--header 'x-apikey: xxx'

---

### **Q: How do I reduce the number of fields returned by the API for IoCs?** 

**A**:  You can do this by using the exclude\_attributes query parameter. This allows you to specify and exclude certain fields from the API response, which should significantly improve efficiency. 

For example, you can use it like this: https://www.virustotal.com/api/v3/files/91e359e98df513ef6ce1fad21ddb8cea02eee0339c77a6dcf7d2e2ea451b4bd1?exclude\_attributes=last\_analysis\_results,sigma\_analysis\_summary,sigma\_analysis\_results,names,signature\_info,pe\_info,sigma\_analysis\_stats,exiftool,crowdsourced\_ids\_results,detectiteasy

---

### **Q: How can I avoid the 40 item limit in the collections API?** 

**A**:  In order to mitigate the quota consumption you can replace the '[https://www.virustotal.com/api/v3/collections](https://www.virustotal.com/api/v3/collections)' endpoint by the '[https://www.virustotal.com/api/v3/intelligence/search](https://www.virustotal.com/api/v3/intelligence/search)'  endpoint, the main advantage is the pagination limit is 300 instead of 40, but you are still required to request for the relationships objects if you need them.

Using the intelligence endpoint requires some changes to the filter you use, for instance, you have to use the **collection** type filter, your query should start with something like **`` 'collection_type:vulnerability entity:collection` ``**

Note: the `exclude_attributes` query parameter also works on the v3/intelligence/search endpoint. 

## **Additional Resources**

* **GTI Documentation Hub**: [https://gtidocs.virustotal.com/](https://gtidocs.virustotal.com/)  
* **GTI API Reference**: [https://gtidocs.virustotal.com/reference/api-overview](https://gtidocs.virustotal.com/reference/api-overview)  
* **Google Cloud Security Community**: [https://www.googlecloudcommunity.com](https://www.googlecloudcommunity.com)
