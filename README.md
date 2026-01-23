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

## 🧪 KQL Walkthrough (Queries + Why They Matter)

### A) Establish victim identity, role, and MFA posture
```kql
Employees
| where name contains "Afomiya"
