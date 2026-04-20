# LetsDefend Walkthrough: SOC141 - Phishing URL Detected

## Alert Overview
* **Event ID:** 86
* **Rule:** SOC141 - Phishing URL Detected
* **Severity:** High
* **Date & Time:** Mar, 22, 2021, 09:23 PM
* **Source IP / Hostname:** 172.16.17.49 / EmilyComp
* **Destination IP / Hostname:** 91.189.114.8 / mogagrocol.ru
* **Domain name:** nichost.ru
* **URL:** http://mogagrocol.ru/wp-content/plugins/akismet/fv/index.php?email=ellie@letsdefend.io
* **User Agent:** Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36


##  Incident Analysis

### 1. Initial Triage
The alert indicates that a user on the network accessed a known phishing URL.

### 2. URL analysis
I analyzed URL in sandboxes to check if the url is malicious or not. According to AnyRun, VirusTotal and Hybrid Analysis the URL is malicious.


You can use the free products/services below.

### 2. Log Management & Traffic Analysis
I navigated to the Log Management tab and filtered for the Source IP to confirm the traffic.
* **Findings:** [Did the connection actually happen? Was there a successful HTTP GET request? Was it blocked or allowed?]
* *(Insert screenshot of the log management screen here)*
- When was it accessed? Mar, 22, 2021, 09:23 PM
- What is the source address? 172.16.17.49
- What is the destination address? 91.189.114.8
- Which user tried to access? EmilyComp
- What is User Agent? Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36
- Is the request blocked? allowed

### 3. OSINT Investigation
I analyzed the requested URL and Destination IP using third-party threat intelligence tools:
* **VirusTotal:** [Explain the results. How many security vendors flagged it? What is it classified as?]
* **URLScan / HybridAnalysis:** [Add any sandbox execution results if applicable.]
* *(Insert screenshot of VirusTotal results here)*

### 4. Endpoint Security
I checked the compromised host in the Endpoint Security tab to see if a payload was dropped or executed.
* **Browser / Command History:** [Did the user actually open the browser? Did they download anything?]
* *(Insert screenshot of the endpoint terminal or process list here)*

##  Containment & Remediation
* **Action Taken:** [e.g., Isolated the machine, deleted malicious email]
* **Reasoning:** [Explain why you took this action—for example, to prevent lateral movement or data exfiltration while the machine is remediated.]

## 📝 Conclusion
* **Result:** [True Positive / False Positive]
* **Summary:** This was a confirmed phishing attempt where the user [did/did not] interact with the payload. The threat was successfully contained, and the alert was closed as a True Positive.
