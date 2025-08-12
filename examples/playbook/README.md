# Google Threat Intelligence (GTI) Workflows for SOAR Platforms

This repository provides workflows and playbooks for integrating **Google Threat Intelligence (GTI)** with various **Security Orchestration, Automation, and Response (SOAR)** platforms. These resources are designed to automate security tasks, connect different security systems, and reduce the need for manual intervention.

A **workflow** is a series of automated steps that allows you to leverage GTI data for critical security operations like **Indicator of Compromise (IOC) enrichment**, **alert triage**, and **threat hunting**.


## Overview

The workflows in this repository enable security teams to build automated playbooks that incorporate GTI data into key scenarios where it adds significant value. This includes tasks like fetching personalized IOC streams for continuous threat monitoring. Each workflow comes with clear documentation, customization options, and is designed for easy integration with your SOAR platform's playbook builder.


## Key Features

  - **Automated Workflows:** Leverage workflows to automate tasks and integrate security systems, making your operations more efficient.
  - **GTI Data Integration:** Use GTI enrichment actions to build powerful playbooks for tasks like phishing analysis, alert triage, and threat hunting.
  - **Out-of-the-Box Playbooks:** Get predefined playbooks or blocks for popular use cases, complete with clear documentation for easy customization.
  - **Maintenance and Testing:** Playbooks are regularly updated and tested against new API and platform versions to ensure they are reliable and error-free.
  - **UX Optimization:** Intuitive naming (e.g., "GTI - Enrich IOCs") and logical grouping make playbooks easy to find and use.


## Workflow: Get IOC Stream Notifications from GTI

This repository includes an example workflow to demonstrate GTI integration.

  - **Purpose:** To fetch a user’s curated personalized IOC streams as configured on the Google Threat Intelligence platform.

  - **Key Features:**
  
      - **IOC Stream Retrieval:** Retrieves personalized IOC streams directly from GTI.
      - **Webhook Integration:** Sends notifications containing the IOC stream data to your SOAR platform via a webhook after the workflow runs.
      - **Customization Support:** Allows for optional filtering of notifications to retrieve only the data you need.


## How to Run the Workflow

To set up and run the example workflow in your SOAR platform, follow these steps:

1.  **Select the Workflow:** In your SOAR platform, choose the "**Get IOC Stream Notifications from GTI**" workflow.
2.  **Edit the Workflow:** Click on the "**Edit in Builder**" button to customize it.
3.  **Configure the Action:** Click on the "**IOC Stream Notifications**" action. You can provide an optional filter to narrow down the notifications. Click "**Save Step**" when you're done.
4.  **Enable the Workflow:** Click the toggle button to turn the workflow on.
5.  **Run the Workflow:** Click the three dots and then "**Run workflow**" to execute it.
6.  **Review Notifications:** Once the workflow is complete, notifications will be sent to your SOAR platform via a webhook.
7.  **Disable the Workflow (Optional):** Click the toggle button to turn the workflow off.
