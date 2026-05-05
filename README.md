# 🔏RDP Brute Force Attack Investigation – Microsoft Sentinel Lab

## The Incident

A Microsoft Sentinel alert fired at 5:30 AM on May 2: **RDP Brute Force Detected from 103.108.141.126**. High severity. Multiple failed login attempts targeting a Windows Server VM exposed to the internet. The kind of thing that makes you check your inbox at 6 AM.

This writeup documents how I investigated it end-to-end: validated the threat, mapped the attack, contained it, and closed it out.

---

## Lab Environment

- **Target:** Azure Windows Server 2022 VM with RDP exposed to the internet
- **Detection layer:** Microsoft Sentinel + Log Analytics workspace
- **IDS layer:** Suricata on Ubuntu 24.04 VM (for network-level confirmation)
- **Attacker IP:** 103.108.141.126 (flagged by multiple security vendors on VirusTotal)

---

## Lab Scope
This is a single-incident investigation lab. In production environments, SOC teams handle 50+ alerts/day with automated response (SOAR), multi-team coordination, and formal escalation workflows. This lab demonstrates the core investigative methodology."

---

## Investigation: From Alert to Closure

### 1. The Alert Fires – Sentinel Catches the Attempt

Sentinel's built-in detection rule triggered on suspicious RDP activity. The alert showed:
- **Source IP:** 103.108.141.126
- **Target accounts:** Administrator, multiple privileged and standard user accounts
- **Volume:** Multiple failed login attempts clustered within minutes
- **MITRE ATT&CK mapping:** T1110.003 (Credential Stuffing / Brute Force)

This pattern screamed brute force. But at this stage, it's just an alert. I needed to validate it against actual logs.

**Screenshot:** Initial alert view in Sentinel showing incident #146 with High severity classification.

<img width="1920" height="1080" alt="sentinel-overview-alerts" src="https://github.com/user-attachments/assets/6f997ec6-71c9-4dce-a7d8-5e8580618675" />

---

### 2. Dig Into the Logs – KQL Query for Evidence

I wrote a KQL query to pull the actual failed login events (Event ID 4625) from the Windows Security log:

```kql
let attacker = "103.108.141.126";
SecurityEvent
| where EventID == 4625
| where IpAddress == attacker
| project TimeGenerated, Computer, Account, IpAddress, EventID, Activity
| order by TimeGenerated desc
```

**What this told me:**
- ~50 failed login attempts in the time window
- Each attempt tried a different account (spray pattern, not focused on one user)
- All attempts came from the same external IP
- No successful login events (Event ID 4624) from this IP in the logs
- Failed attempts stopped after the firewall rule was applied

**Why this matters:** The spray pattern (multiple accounts, single IP) is a classic brute force signature. If it were a typo or legitimate user lockout, we'd see repeated attempts on one account from different IPs. This is organized.

**Screenshot:** KQL query results showing the full list of failed login events with timestamps, accounts, and source IP.

<img width="1920" height="1080" alt="kql-bruteforce-query" src="https://github.com/user-attachments/assets/c3d1b320-5ad9-417c-94d6-0ee3af5488af" />

Note: Query screenshot shows a subset of events from the attacker IP; Sentinel incident summary recorded ~50 attempts in total.

---

### 3. Map the Entities – Sentinel's Investigation Graph

I used Sentinel's built-in investigation graph to visualize relationships between entities:

- **Central node:** External IP 103.108.141.126
- **Connected nodes:** Windows Server VM, multiple user accounts, firewall rules
- **Edge labels:** Failed login attempts, inbound network traffic

The graph showed a single attacker IP attempting to reach multiple accounts on one target system. No lateral movement, no successful pivot. This was an **external reconnaissance attempt**, not a breach.

**Screenshot:** Investigation graph showing the IP, target VM, and affected user accounts as interconnected nodes.

<img width="1920" height="1080" alt="investigation-graph-entities" src="https://github.com/user-attachments/assets/a62d7667-e1c3-46e8-b38f-4cf6cf9edf8a" />

---

### 4. Threat Intelligence Lookup – VirusTotal Validation

I checked the attacker IP on VirusTotal to see if it had any reputation history:

**Results:**
- Flagged by 10 security vendors as malicious
- Known for SSH and RDP scanning (exactly what we're seeing)
- Active in the last 30 days across multiple target IPs
- Likely part of an automated botnet or scanning tool

**Conclusion:** This isn't a one-off mistake or a misconfigured service. It's a known attacker actively hunting for open RDP ports.

**Screenshot:** VirusTotal report showing vendor detections and historical data for the IP.

<img width="1920" height="1080" alt="ip-threat-intel-virustotal" src="https://github.com/user-attachments/assets/08f6f4f8-da90-4f87-b0e0-6af4f2f9426c" />

---

### 5. Network-Level Confirmation – Suricata IDS Logs

I checked the Suricata IDS logs on the Ubuntu VM to see if the network layer also captured the attack:

**Findings:**
- Suricata rules triggered for suspicious RDP traffic patterns
- Inbound SYN packets on port 3389 followed by rapid connection resets (sign of scanning/probing)
- No successful RDP session established

**Why this matters:** SIEM and IDS agree. The attack is real and visible at multiple layers.

**Screenshot:** Suricata alert logs showing the attack pattern (connection attempts, timeouts, resets).

<img width="1920" height="1020" alt="suricata-alerts-terminal" src="https://github.com/user-attachments/assets/0fb8c53d-172b-4b58-b7a2-9ecd16a08fef" />

---

## Assessment – True Positive, No Breach

After correlating all evidence:

✅ **Alert is valid** – Confirmed malicious IP and brute force pattern  
✅ **Attack unsuccessful** – No successful login, no credential theft  
✅ **System secure** – No lateral movement or persistence observed  
✅ **Threat is external** – No internal compromise indicators  

**Verdict:** True Positive. Attack contained. Proceeding to remediation.

---

## Response & Containment

### Action 1: Block the IP – Windows Firewall Rule

Created a firewall rule to block inbound traffic from 103.108.141.126:

```
Rule name: Block Brute Force Attacker
Direction: Inbound
Source IP: 103.108.141.126
Protocol: Any
Action: Block
```

Applied and verified. Subsequent login attempts from this IP were immediately rejected at the firewall.

**Screenshot:** Windows Defender Firewall console showing the active block rule.

<img width="1767" height="1080" alt="windows-firewall-block-rule" src="https://github.com/user-attachments/assets/a4e1270e-40c2-45c0-bbbe-0947b01c9cab" />

---

### Action 2: Restrict RDP Access – Azure NSG Rule

Modified the Azure Network Security Group to allow RDP (port 3389) only from trusted IPs (my own subnet):

```
Rule priority: 100
Direction: Inbound
Source: My trusted IP range
Destination Port: 3389
Action: Allow

Rule priority: 101
Direction: Inbound
Source: Any
Destination Port: 3389
Action: Deny
```

This ensures RDP is no longer exposed to the entire internet. Only legitimate traffic from known networks can reach it.

**Screenshot:** Azure NSG rules in the portal showing the new RDP restriction.

<img width="1920" height="1080" alt="azure-nsg-rdp-restriction" src="https://github.com/user-attachments/assets/38cbe066-6097-4dbc-ad1c-8f09600a1a70" />

---

### Action 3: Enforce Account Lockout Policy

Configured Windows Account Lockout policy to prevent unlimited brute force attempts:

```
Threshold: 5 failed attempts
Lockout duration: 15 minutes
Reset count: 15 minutes of inactivity
```

Now, any account that gets hammered with failed logins will automatically lock for 30 minutes, stopping the attacker cold.

**Screenshot:** Group Policy editor showing the updated Account Lockout Policy settings.

<img width="1767" height="888" alt="account-lockout-policy" src="https://github.com/user-attachments/assets/7274c2a2-f630-4bcd-aaae-86ad79978ff8" />


---

### Action 4: Close the Incident

After verifying all remediation steps:
- Firewall rule active ✓
- NSG rule deployed ✓
- Account lockout policy enforced ✓
- No further attacks from this IP observed ✓

Incident #146 marked as **Closed** with classification: **True Positive – Attack Contained**.

<img width="1920" height="1080" alt="rdp-alert-closed" src="https://github.com/user-attachments/assets/ac3a0336-72a7-4f86-a002-b29210f1f0b8" />

---

## What I Learned

**Technical:**
- Writing KQL queries to hunt failed login patterns (Event ID 4625 vs 4624)
- Using Sentinel's investigation graph to understand attack scope
- Correlating SIEM alerts with IDS logs for multi-layer validation
- Practical Azure NSG rules for network segmentation
- Account lockout policies as a brute force defense

**Investigative mindset:**
- Don't trust the alert alone—validate with raw logs
- Threat intelligence (VirusTotal) confirms whether a threat is "known bad"
- Multiple data sources beat one source (SIEM + IDS agreement is stronger than either alone)
- The absence of successful logins is as informative as the presence of failed ones
- Remediation should happen in layers (firewall, network, policy, monitoring)

**For future labs:**
- Implement multi-factor authentication earlier in the setup
- Use conditional access policies in Azure to block high-risk locations
- Set up log retention and alerting for account lockout events
- Document the cost of leaving RDP exposed (even in a lab)

---

## Tools & Techniques

| Tool | Purpose |
|------|---------|
| **Microsoft Sentinel** | Alert generation, investigation graph, incident management |
| **KQL** | Query Windows Security logs for Event ID 4625 (failed logins) |
| **VirusTotal** | IP reputation lookup and threat history |
| **Azure NSG** | Network-level access control |
| **Suricata IDS** | Network traffic analysis and suspicious pattern detection |
| **Windows Firewall** | Host-level blocking rules |
| **Group Policy** | Account lockout policy enforcement |

---

## Key Takeaway

This lab demonstrates a complete SOC Level 1 investigation cycle: **detect → validate → investigate → remediate → close**. The emphasis is on not taking alerts at face value, but validating them with actual log evidence, external intelligence, and multi-layer correlation. That's the mindset that makes SOC analysts valuable.

---
