# KC7-CloutHaus — Inside the Clout Breach 🐾  
## Phishing → Email Compromise → Exfiltration via Auto-Forwarding (KQL Case Study)

This repo documents a full KQL investigation in Azure Data Explorer (ADX) that traces a targeted spear-phishing campaign against a CloutHaus influencer partner, leading to mailbox compromise and **stealthy exfiltration via forwarded emails** (often **without attachments**, using cloud links instead).

---

## 📌 Scenario (Lab Summary)

An influencer partner at CloutHaus (“Afomiya Storm”) was targeted with a spear-phishing email impersonating Dior. After clicking a malicious link and entering a username, an attacker gained mailbox access from a foreign IP using an anomalous legacy User-Agent. The attacker performed reconnaissance via web searches, then exfiltrated sensitive documents (passport scan, bank/tax documents) using **forwarding behavior** that did not require persistent interactive logins.

---

## 🧰 Tools & Data Sources

**Platform:** Azure Data Explorer (ADX)  
**Language:** KQL (Kusto Query Language)

**Tables used:**
- `Employees`
- `Email`
- `OutboundNetworkEvents`
- `InboundNetworkEvents`
- `PassiveDns`

---

## 🎯 Investigation Objectives

- Identify the victim’s corporate identity and risk posture (**role + MFA status**)
- Find the phishing email artifact and the malicious link clicked
- Pivot from phishing domain → hosting IP → related infrastructure
- Identify suspicious mailbox login (source IP + geo + anomalous User-Agent)
- Reconstruct reconnaissance behavior from inbound web search activity
- Detect email exfiltration via forwarding and identify sensitive data impacted

---

## ✅ Key Findings (What I Proved)

### 1) Identity / Risk Context
- **Victim:** `afomiya_storm@clouthaus.com`
- **Role:** Influencer Partner
- **MFA:** Disabled (`false`) → elevated takeover risk

### 2) Phishing & Infrastructure
- **Phishing sender:** `collabs@dior-partners.com`
- **Malicious link:** `https://super-brand-offer.com/login`
- **Click timestamp:** `2025-04-03T11:20:00Z`
- **Phishing domain → IP:** `198.51.100.12`
- **Infra reuse:** PassiveDNS showed **3 distinct domains** hosted on the same IP

### 3) Compromise Indicators / Attribution Artifacts
- **Suspicious login IP:** `182.45.67.89`
- **Geo:** China (Jinan, Shandong)
- **User-Agent anomaly:** `MSIE 5.0` / `Windows NT 5.2` (consistent with attacker tooling/spoofing)
- **PassiveDNS domains on attacker IP:**  
  - `influencer-deals.net`  
  - `dior-partners.com`

### 4) Reconnaissance & Targeting
- Attacker “search history” in `InboundNetworkEvents` indicated intent to obtain the victim’s **location** (OSINT-driven recon), not technical endpoints.

### 5) Exfiltration via Forwarding (High Impact)
Forwarded messages were detected using:
- `reply_to == "afomiya_storm@clouthaus.com"`
- external recipient domain (**not** `@clouthaus.com`)

Sensitive forwarded subjects included:
- **Passport scan:** `[EXTERNAL] [FORWARD] Afomiya's passport scan – confidential`
- **Bank / tax docs:** identified via subject keyword hunting (Bank Statement / W-2 / 1099 / Year-End)

> **Important:** Some exfil events had **no file attachments** because data was shared via **external links (Drive/Docs)**. This is realistic BEC/identity-theft tradecraft to evade attachment-based detection.

---

Identify role
Employees
| where name contains "Afomiya"
| distinct role


Purpose:
Determine target value and exposure. Influencer Partner roles attract phishing due to frequent external communication.

Check MFA status
Employees
| where name contains "Afomiya"
| distinct mfa_enabled


Purpose:
Assess account protection level. MFA was disabled, increasing compromise risk.

2️⃣ Phishing Email Discovery
Locate Dior-themed phishing email
Email
| where recipient == "afomiya_storm@clouthaus.com"
| where subject contains "Dior" or links contains "Dior"


Purpose:
Identify spear-phishing messages impersonating a luxury brand.

3️⃣ Confirm Phishing Link Click
Validate outbound connection to phishing domain
OutboundNetworkEvents
| where url contains "super-brand-offer.com"


Purpose:
Confirm the user interacted with the malicious infrastructure.

4️⃣ Infrastructure Pivoting (Domain → IP → Reuse)
Resolve phishing domain
PassiveDns
| where domain contains "super-brand-offer.com"


Purpose:
Identify the hosting IP behind the phishing site.

Identify infrastructure reuse
PassiveDns
| where ip contains "198.51.100.12"
| distinct domain


Purpose:
Detect reuse of hosting infrastructure across multiple malicious domains.

5️⃣ Inbound Reconnaissance Analysis
Pull inbound activity from attacker IP
InboundNetworkEvents
| where timestamp between (datetime(2025-03-01T11:58:00Z) .. datetime(2025-04-03T12:20:00Z))
| where src_ip contains "182.45.67.89"


Purpose:
Identify pre-attack reconnaissance behavior.

Extract URL paths to interpret intent
InboundNetworkEvents
| where src_ip contains "182.45.67.89"
| where method in ("GET", "POST")
| project parse_path(url)


Purpose:
Reveal attacker intent by analyzing URL patterns rather than raw traffic.

Finding:
Recon focused on the victim’s location, consistent with OSINT-driven targeting.

6️⃣ Attacker Attribution via PassiveDNS
Identify domains linked to attacker IP
PassiveDns
| where ip contains "182.45.67.89"
| distinct domain


Purpose:
Correlate malicious login activity with phishing infrastructure.

7️⃣ Email Exfiltration Detection (Critical Phase)
Validate Email table schema
Email
| take 5


Purpose:
Confirm available fields (reply_to, links, attachments) before hunting exfiltration.

Quantify external email flow
Email
| extend RecipDomain = tostring(split(recipient, "@")[1])
| summarize Total=count(), External=countif(RecipDomain != "clouthaus.com")


Purpose:
Establish baseline and confirm external email volume suitable for exfiltration analysis.

Identify forwarded emails (exfiltration pivot)
let victim = "afomiya_storm@clouthaus.com";
Email
| where reply_to == victim
| where recipient !endswith "@clouthaus.com"
| project timestamp, subject, sender, recipient, links, attachments
| order by timestamp asc


Purpose:
Forwarded messages preserve mailbox ownership via reply_to, not sender.
This pivot reveals auto-forwarded exfiltration.

Detect identity document exfiltration (passport)
let victim = "afomiya_storm@clouthaus.com";
Email
| where reply_to == victim
| where recipient !endswith "@clouthaus.com"
| where subject has_any ("passport","ID","KYC","verification","travel")
| project timestamp, subject, recipient, links, attachments
| order by timestamp asc


Purpose:
Identify identity-theft-grade data exfiltration.
Documents were shared via cloud links, not attachments.

Detect financial & tax document exfiltration
let victim = "afomiya_storm@clouthaus.com";
Email
| where reply_to == victim
| where recipient !endswith "@clouthaus.com"
| where subject has_any ("Bank","Statement","Monthly","W-2","1099","Tax","Year-End","Payroll")
| project timestamp, subject, sender, recipient, links, attachments
| order by timestamp asc


Purpose:
Confirm theft of financial documents enabling fraud and tax abuse.

🧠 Key Analyst Takeaways

Forwarded email exfiltration does not require attachments

Ownership is preserved via reply_to, not sender

Cloud links (Drive/Docs) are commonly used to evade DLP

Reconnaissance often precedes visible compromise

Infrastructure reuse enables attacker clustering and attribution

🛡️ Defensive Recommendations

Enforce MFA for high-visibility roles

Alert on foreign logins with anomalous User-Agents

Monitor spikes in external recipients after authentication events

Inspect cloud links in forwarded emails with sensitive keywords

Track domain → IP → domain pivots using PassiveDNS

🧭 MITRE ATT&CK Mapping

Reconnaissance: OSINT / Victim Identity & Location (T1589 / T1593)

Initial Access: Spearphishing Link (T1566.002)

Credential Access: Phishing Credential Harvesting

Collection: Email Collection / Forwarding Abuse (T1114.003)

Exfiltration: Attachmentless Exfiltration via Cloud Links
Employees
| where name contains "Afomiya"
