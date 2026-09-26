# Security Operations Center (SOC) Automation Workflow Blueprint

## Overview
This workflow automates the initial triage, enrichment, and basic containment of security alerts. By automating the repetitive steps of gathering context for an alert, Junior SOC analysts can focus on decision-making rather than data collection.

---

## 1. Platform & Tools Selection
For Cybersecurity SOC automation, we want a platform that is extremely simple, intuitive, and easy to build with. We will use **Zapier**, as it requires zero coding and has native integrations for most security tools, making it the easiest way to get started.

**Connected Apps:**
*   **Trigger/SIEM:** Splunk, Elastic Security, or Wazuh (Alert Source).
*   **Enrichment/Threat Intel:** VirusTotal (for IP/Hash reputation).
*   **Endpoint Detection & Response (EDR):** CrowdStrike or SentinelOne.
*   **Case Management:** Jira Service Management or TheHive.
*   **Communication:** Slack (SOC Analysts Channel).

---

## 2. Trigger
**Event:** A new High/Medium severity alert is generated in the SIEM (e.g., "Suspicious PowerShell Execution" or "Malware Detected").
*   **Mechanism:** The SIEM sends a JSON payload via a Webhook trigger directly into Zapier (Catch Hook).

---

## 3. Data Flow & Core Actions (The Sequence)

### Step 1: Webhook Trigger & Data Parsing
*   **Action:** Webhook receives the alert payload.
*   **Action:** Parse the JSON to extract key Indicators of Compromise (IoCs) such as Source IP, File Hash (SHA256), and Endpoint Hostname.

### Step 2: Threat Intelligence Enrichment
*   **Action:** VirusTotal API - "Get File Hash Report" or "Get IP Address Report".
*   **Input Data:** The Hash or IP extracted in Step 1.
*   **Output Data:** Reputation score (e.g., number of security vendors flagging it as malicious).

### Step 3: Context Gathering from EDR
*   **Action:** CrowdStrike / SentinelOne API - "Search Endpoint".
*   **Input Data:** Endpoint Hostname from Step 1.
*   **Output Data:** Machine status, currently logged-in user, and network isolation status.

### Step 4: Conditional Routing (Triage Decision)
*   **Action:** Router / Switch Node based on the VirusTotal Score.
*   **Branch A (High Confidence Malicious):** VirusTotal score >= 5 vendors flagged.
*   **Branch B (Suspicious / Unknown):** VirusTotal score between 1 and 4, or not found.
*   **Branch C (Known False Positive):** Internal whitelist match or specific benign criteria.

### Step 5: Automated Actions (Based on Route)

**If Branch A (High Confidence Malicious):**
1.  **Containment:** Send API call to EDR to **Isolate the Endpoint** from the network immediately.
2.  **Ticketing:** Create a Jira Issue. Priority: P1. Attach all VT scores and host context.
3.  **Notification:** Send an urgent Slack message to `#soc-alerts` tagging the on-call analyst: *"🚨 Critical: Endpoint isolated due to known malware. Jira: [Link]"*

**If Branch B (Suspicious / Unknown):**
1.  **Ticketing:** Create a Jira Issue. Priority: P2/P3. Attach VT scores and host context.
2.  **Notification:** Send a standard Slack message to `#soc-alerts` for human review: *"⚠️ Review Needed: Suspicious activity on Host X. Awaiting analyst triage. Jira: [Link]"*

**If Branch C (Known False Positive):**
1.  **Auto-Close:** Send API call back to the SIEM to close the alert with the comment "Auto-closed: Known benign behavior/whitelisted."

---

## 4. Error Handling & Edge Cases

1.  **Threat Intel API Rate Limits:** VirusTotal has strict API limits on free/lower tiers. Use a standard Error Node to catch `429 Too Many Requests`. Add a "Wait/Sleep" module for 60 seconds, then retry the enrichment step.
2.  **Missing Data:** If the SIEM alert doesn't contain a Hash or IP, the workflow should use a Conditional check to skip the VirusTotal enrichment step and route directly to Branch B for human review.
3.  **Containment Failure:** If the API call to isolate the endpoint fails (e.g., endpoint is offline), route an emergency message to Slack: *"CRITICAL ERROR: Failed to isolate Host X. Manual intervention required immediately."*

---

## 5. Step-by-Step Build Instructions (For Zapier)

1.  Create a new **Zap**.
2.  **Trigger:** Choose "Webhooks by Zapier" and select the "Catch Hook" event. Zapier will give you a URL. Configure your SIEM to send alert payloads to this URL.
3.  **Action 1 (Threat Intel):** Add a "VirusTotal" action step (or use Webhooks by Zapier for a custom API call). Map the File Hash variable from the Trigger payload.
4.  **Action 2 (EDR Context):** Add a "CrowdStrike" or "SentinelOne" action step to "Find Endpoint" based on the hostname from Step 1.
5.  **Action 3 (Routing):** Add a **Paths by Zapier** step to split the workflow based on the VirusTotal malicious score.
6.  **Path A (Malicious > 5):**
    *   Add an action to your EDR app to "Contain/Isolate Host".
    *   Add a "Jira Software" action to "Create Issue".
    *   Add a "Slack" action to "Send Channel Message" for the critical alert.
7.  **Path B (Suspicious 0-5):**
    *   Add a "Jira Software" action to "Create Issue".
    *   Add a "Slack" action to "Send Channel Message" for the review request.
8.  Test each step to ensure data maps correctly, then click **Publish Zap**.
