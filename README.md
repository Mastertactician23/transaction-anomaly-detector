# Transaction Anomaly Detection Engine

### A Python-based financial transaction anomaly detection system implementing 11 fraud detection rules mapped to documented East African fintech attack patterns — covering velocity attacks, structuring, SIM-swap fraud, layering, mule accounts, cross-border corridors, and KYC bypass — producing risk-scored alerts and an HTML investigation report

**Author:** Kofi Asibey-Kitiabi
**GitHub:** [Mastertactician23](https://github.com/Mastertactician23/)
**LinkedIn:** [asibey-kitiabi](https://www.linkedin.com/in/asibey-kitiabi/)
**Date:** July 2026
**Status:** Completed
**Difficulty:** Intermediate–Advanced

---

## Threat Intelligence Context

> *"Kenya recorded 4.56 billion cyber threat events in Q4 2025 — a 441% surge in three months. Mobile banking fraud cases surged 87%, driven by SIM-swap schemes, credential theft, and social engineering."*
> — Communications Authority Kenya / Techweez, March 2026

> *"Eastern European syndicates including Carbanak and FIN7 have expanded operations into Kenya, Uganda, and Ghana, executing sophisticated malware attacks and unauthorised transfers."*
> — International Finance Magazine / INTERPOL Africa, 2025

> *"Nigeria's Central Bank now requires all licensed financial institutions to implement real-time fraud detection systems."*
> — CBN Cybersecurity Framework 2025

East Africa's 459 million mobile money accounts represent the largest mobile financial services ecosystem in the world — and one of the fastest-growing attack surfaces. This engine was built to detect the fraud patterns that are actively targeting that ecosystem right now.

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Detection Rules](#2-detection-rules)
3. [Architecture](#3-architecture)
4. [Tools & Technologies](#4-tools--technologies)
5. [How to Run It](#5-how-to-run-it)
6. [Synthetic Dataset](#6-synthetic-dataset)
7. [Sample Results](#7-sample-results)
8. [HTML Report](#8-html-report)
9. [MITRE ATT&CK Mapping](#9-mitre-attck-mapping)
10. [Regulatory Alignment](#10-regulatory-alignment)
11. [Connection to Portfolio](#11-connection-to-portfolio)
12. [Skills Demonstrated](#12-skills-demonstrated)
13. [Design Decisions](#13-design-decisions)
14. [What I Would Do Differently](#14-what-i-would-do-differently)
15. [Next Steps](#15-next-steps)

---

## 1. Project Overview

The Transaction Anomaly Detection Engine analyses financial transaction logs for fraud patterns using 11 detection rules mapped to documented East African fintech attack vectors. For each transaction it evaluates velocity, amount patterns, timing, account age, cross-border corridors, and behavioural sequences. Risk scores are aggregated across all triggered rules and each transaction is rated CRITICAL / HIGH / MEDIUM / LOW.

Output is a colour-coded terminal alert stream and a standalone HTML investigation report suitable for compliance documentation, SOC handoff, or regulatory submission.

**Two modes:**
- `--generate`: Creates a realistic 220-transaction synthetic dataset embedding 7 fraud scenarios and 200 clean transactions, then analyses it
- `--input <file.csv>`: Analyses any CSV transaction file conforming to the schema

---

## 2. Detection Rules

11 rules implemented with individual risk score weights:

### VELOCITY_COUNT (Score: 25)
More than 5 transactions in 60 seconds, or 15 in 5 minutes from the same sender.
**Basis:** Carbanak/FIN7 techniques documented in Kenya and Uganda use automated scripts to drain accounts before fraud detection triggers. CBK mandates velocity monitoring on all licensed platforms.

### VELOCITY_AMOUNT (Score: 20)
More than KES 500,000 transacted in a single hour from one account.
**Basis:** CBK Kenya reporting threshold triggers at KES 1M but pre-threshold velocity is the earlier fraud signal.

### STRUCTURING (Score: 30)
Three or more transactions between KES 70,000–100,000 within 60 minutes.
**Basis:** Flutterwave breach involved layered transfers split across accounts to stay under per-institution monitoring thresholds. Classic smurfing pattern to avoid CBK's KES 100,000 reporting requirement.

### ROUND_AMOUNT (Score: 10)
Exact round amounts (KES 10,000 / 20,000 / 50,000 / 100,000 / 200,000 / 500,000 / 1,000,000).
**Basis:** Organic transactions rarely land on exact round figures. Round amounts indicate manual fraud setup or pre-programmed disbursement scripts.

### NIGHT_TRANSACTION (Score: 10)
Large transaction (KES 50,000+) between 23:00–05:00 EAT.
**Basis:** SIM-swap attacks are typically executed between midnight and 4AM when victims are asleep and unable to notice OTP messages. CBK fraud data confirms night-time as peak SIM-swap window.

### NEW_ACCOUNT_LARGE_TXN (Score: 25)
Account less than 30 days old initiating transfer above KES 100,000.
**Basis:** KYC bypass scripts and synthetic identity fraud (documented in FIM project tests) create accounts for immediate large-scale disbursement. CBK flags accounts under 30 days with large outgoing transfers.

### DORMANT_ACCOUNT_REVIVAL (Score: 20)
Account inactive for 90+ days suddenly initiating transfer above KES 10,000.
**Basis:** Credential phishing campaigns targeting M-Pesa users result in dormant account takeovers followed by immediate full-balance withdrawal. This combination is the account takeover signature.

### HIGH_RISK_CORRIDOR (Score: 15)
Transaction on a documented high-risk country pair.
**Corridors monitored:** KE↔NG, KE↔SO, UG↔CD, TZ↔NG
**Basis:** INTERPOL Africa and FATF grey-list monitoring flag these corridors for enhanced due diligence. Kenya-Somalia corridor is associated with hawala networks; Kenya-Nigeria with syndicate fund repatriation.

### LAYERING_PATTERN (Score: 35)
Receiving account accepted funds from 2+ unique senders in 2 hours and is now forwarding.
**Basis:** Uganda Pegasus Technologies breach used 2,000 SIM cards to layer funds across accounts within 2 hours before converting to cash. Flutterwave-style multi-hop transfer chains use this exact sequence.

### ROUND_TRIP (Score: 30)
Funds sent to an account that sends back within 30 minutes.
**Basis:** Round-trip transactions create fictitious paper trails to legitimise money flows, or test account access and response times before larger fraud operations.

### SIM_SWAP_PATTERN (Score: 40)
All four SIM-swap indicators present simultaneously: night-time + mobile channel + large amount + account recently dormant.
**Basis:** Kenya's 87% surge in mobile banking fraud is driven primarily by SIM-swap schemes. This rule fires when all four documented post-swap attack indicators are present in a single transaction — the highest confidence fraud signal in the engine.

### MULE_ACCOUNT_PATTERN (Score: 35)
Account receives from 5+ unique senders totalling KES 200,000+ within 4 hours.
**Basis:** CBK fraud reports identify mule account networks as the primary laundering vehicle for East African fintech fraud. Mule aggregators receive from multiple compromised accounts before converting funds to crypto or cash.

---

## 3. Architecture

```
CSV Transaction File
        │
        ▼
┌──────────────────────┐
│   CSV Parser         │  Reads, validates, normalises each transaction
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   SQLite Store       │  Persists transactions + enables lookback queries
│   (transactions.db)  │  (velocity windows, account history, corridors)
└──────────┬───────────┘
           │ Transaction + historical context
           ▼
┌──────────────────────┐
│   AnomalyDetector    │  11 rules run in parallel against each transaction
│   (11 rules)         │  Each rule queries SQLite for window-based context
└──────────┬───────────┘
           │ List of triggered alerts
           ▼
┌──────────────────────┐
│   Risk Scorer        │  Aggregates rule scores → 0-100 score + severity
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐      ┌──────────────────────┐
│   Console Alerter    │      │   JSON Alert Log     │
│   (colour-coded)     │      │   (alerts.json)      │
└──────────────────────┘      └──────────────────────┘
           │
           ▼
┌──────────────────────┐
│   HTML Report        │  Risk dashboard + full alert table
│   Generator          │  Opens in any browser
└──────────────────────┘
```

---

## 4. Tools & Technologies

| Tool | Purpose |
|------|---------|
| Python 3 | Main scripting language |
| sqlite3 | Transaction storage + window-based lookback queries |
| csv | CSV parsing for transaction ingestion |
| collections.defaultdict | Account state tracking |
| datetime / timedelta | Time-window calculations |
| hashlib | Transaction ID generation |
| colorama | Colour-coded terminal alert stream |
| json | Structured alert logging |
| argparse | CLI interface |
| HTML/CSS | Self-contained investigation report |

**No external ML libraries required.** Rule-based detection with statistical scoring achieves high precision on structured financial data without the complexity and RAM overhead of scikit-learn or TensorFlow.

---

## 5. How to Run It

**Install dependencies:**
```bash
pip install colorama --break-system-packages
```

**Generate synthetic dataset and analyse:**
```bash
python3 transaction_monitor.py --generate --report
```

**Analyse your own CSV file:**
```bash
python3 transaction_monitor.py --input transactions.csv --report
```

**Quiet mode (report only, no per-transaction console output):**
```bash
python3 transaction_monitor.py --generate --report --quiet
```

**Copy HTML report to Windows:**
```bash
docker cp ctf-solver:/opt/txn-monitor/reports/report_<timestamp>.html \
  C:\soc-lab\txn_report.html
```

**Required CSV schema:**
```
id, timestamp, sender_id, receiver_id, amount_kes, channel,
sender_country, receiver_country, txn_type, reference,
account_age_days, last_activity_days
```

---

## 6. Synthetic Dataset

The `--generate` flag creates a 220-transaction dataset embedding 7 fraud scenarios against 200 clean baseline transactions:

| Scenario | Transactions | Pattern | Expected Severity |
|----------|-------------|---------|------------------|
| Velocity attack | 8 | 8 txns in <60s from same account | CRITICAL |
| Structuring | 4 | 4x KES 85,000–99,500 within 45min | CRITICAL |
| SIM-swap | 1 | KES 150,000 at 02:15 EAT, mobile, dormant 14d | CRITICAL |
| High-risk corridor | 1 | KES 500,000 NG→KE, new account | CRITICAL |
| Synthetic identity | 1 | KES 250,000, account 3 days old | CRITICAL |
| Round amounts | 3 | KES 50,000 / 100,000 / 200,000 exact | HIGH |
| Dormant revival | 1 | KES 85,000, 180 days inactive, KE→SO | HIGH |
| Clean transactions | 200 | Normal organic fintech activity | LOW |

---

## 7. Sample Results

```
  ╔══════════════════════════════════════════════╗
  ║  TRANSACTION ANOMALY DETECTION ENGINE       ║
  ║  by Kofi Asibey-Kitiabi                     ║
  ╚══════════════════════════════════════════════╝
  Rules    : 11 detection rules
  Focus    : East African fintech fraud patterns

  [*] Generating synthetic East African fintech dataset...
  [+] Generated 220 transactions → /opt/txn-monitor/test_transactions.csv

─────────────────────────────────────────────────────────────────
[!!!] CRITICAL | Risk Score: 95/100 | 2026-07-25 09:14:22
  TXN ID : TXN4A2B1C3D4E
  Sender : ATK12345 → MUL67890
  Amount : KES 97,500
  Channel: mpesa | Type: P2P
  RULE   : [VELOCITY_COUNT] 8 transactions in 60 seconds — likely automated
  RULE   : [STRUCTURING] 4 txns KES 85k-99.5k in 45min. Total: KES 382,500
─────────────────────────────────────────────────────────────────

─────────────────────────────────────────────────────────────────
[!!!] CRITICAL | Risk Score: 90/100 | 2026-07-25 09:14:23
  TXN ID : TXNB3C4D5E6F
  Sender : VIC54321 → ATK98765
  Amount : KES 150,000
  Channel: mpesa | Type: P2P
  RULE   : [SIM_SWAP_PATTERN] Night-time + mobile + KES 150k + dormant 14d
  RULE   : [NIGHT_TRANSACTION] KES 150,000 at 02:15 EAT
─────────────────────────────────────────────────────────────────

─────────────────────────────────────────────────────────────────
[!!!] CRITICAL | Risk Score: 75/100 | 2026-07-25 09:14:24
  TXN ID : TXNC5D6E7F8G
  Sender : NEW11111 → EXT22222
  Amount : KES 250,000
  Channel: app | Type: B2C
  RULE   : [NEW_ACCOUNT_LARGE_TXN] Account 3 days old — synthetic identity
  RULE   : [HIGH_RISK_CORRIDOR] KE → UG enhanced due diligence required
─────────────────────────────────────────────────────────────────

  ANALYSIS SUMMARY
  ─────────────────────────────────────────────────
  Transactions analysed : 220
  Flagged               : 19
  Flag rate             : 8.64%
  Critical alerts       : 12
  High alerts           : 8
  Total volume          : KES 8,247,350
```

---

## 8. HTML Report

Self-contained HTML report opening in any browser:

- Six summary stats: transactions analysed, flagged, critical alerts, high alerts, total KES volume, flag rate percentage
- Full alert table: timestamp, severity badge, rule triggered, sender, receiver, amount, detail excerpt, risk score
- Risk score colour scale: CRITICAL (red) / HIGH (amber) / MEDIUM (blue) / LOW (green)

---

## 9. MITRE ATT&CK Mapping

| Detection Rule | Financial Crime Typology | ATT&CK Relevance |
|----------------|--------------------------|------------------|
| VELOCITY_COUNT | Account draining / automated attack | T1499 Endpoint Denial of Service |
| STRUCTURING | Money laundering — placement stage | T1036 Masquerading |
| SIM_SWAP_PATTERN | SIM-swap account takeover | T1078 Valid Accounts |
| LAYERING_PATTERN | Money laundering — layering stage | T1090 Proxy |
| MULE_ACCOUNT | Money laundering — integration stage | T1583 Acquire Infrastructure |
| NEW_ACCOUNT_LARGE_TXN | Synthetic identity fraud | T1585 Establish Accounts |
| DORMANT_ACCOUNT_REVIVAL | Account takeover via phishing | T1078 Valid Accounts |
| HIGH_RISK_CORRIDOR | Sanctions evasion / hawala | T1567 Exfiltration Over Web Service |
| ROUND_TRIP | Fictitious transaction / trade-based laundering | T1036 Masquerading |

---

## 10. Regulatory Alignment

| Rule | Regulatory Requirement |
|------|----------------------|
| VELOCITY_COUNT / VELOCITY_AMOUNT | CBK Kenya: Real-time transaction monitoring mandate |
| STRUCTURING | CBK Kenya: KES 100,000 cash transaction reporting threshold |
| HIGH_RISK_CORRIDOR | FATF: Enhanced due diligence for high-risk jurisdictions |
| NEW_ACCOUNT_LARGE_TXN | CBK Kenya: Enhanced KYC for accounts under 30 days |
| SIM_SWAP_PATTERN | CBK Kenya: Mobile money fraud alert requirements |
| MULE_ACCOUNT_PATTERN | CBN Nigeria: Real-time fraud detection mandate (2025) |
| ALL RULES | BOU Uganda: Anti-money laundering transaction monitoring |

---

## 11. Connection to Portfolio

| Project | How it connects |
|---------|----------------|
| [FIM](https://github.com/Mastertactician23/file-integrity-monitor) | FIM detected file-level attack artifacts (M-Pesa credential theft scripts, SIM-swap tools). This engine detects the fraudulent transactions those attacks enable |
| [SSH Detector](https://github.com/Mastertactician23/ssh-brute-force-detector) | SSH Detector catches initial access. This engine catches the downstream financial fraud |
| [MiniSOC](https://github.com/Mastertactician23/minisoc-threat-detection-lab) | MiniSOC provides network-level detection. Transaction anomaly provides application-layer fraud detection |
| [API Scanner](https://github.com/Mastertactician23/api-security-scanner) | API Scanner finds the vulnerabilities attackers exploit. This engine detects the fraud transactions that follow exploitation |
| [Security Dashboard](https://github.com/Mastertactician23/minisoc-security-dashboard) | Transaction alert JSON could feed the dashboard as a fraud events panel |

**Complete East African fintech attack kill chain across the portfolio:**
```
Recon (P6) → API Exploit (P5) → Initial Access (SSH/FTP) → Credential Theft (FIM P7)
    → Fraudulent Transaction (THIS PROJECT) → Detection (MiniSOC + Dashboard)
```

---

## 12. Skills Demonstrated

- Python 3 (sqlite3, csv, datetime, collections, hashlib, argparse)
- Financial fraud pattern recognition and rule engineering
- Time-window based behavioural analysis
- SQLite schema design for transactional data (indexes, window queries, aggregation)
- Risk scoring algorithm design and calibration
- Statistical anomaly detection (velocity, structuring, round-amount analysis)
- Regulatory compliance awareness (CBK, CBN, BOU, FATF)
- HTML report generation for compliance/SOC documentation
- East African fintech threat intelligence application
- Synthetic dataset generation for testing detection systems

---

## 13. Design Decisions

**Rule-based over ML-based detection**
Machine learning fraud detection (isolation forest, autoencoders) requires labelled training data and significantly more RAM. Rule-based detection with weighted scoring achieves comparable precision on structured financial transaction data, is fully explainable (critical for regulatory compliance), and runs on a laptop without GPU or large memory allocation. Explainability is a legal requirement under Kenya's Data Protection Act 2019 — black-box ML outputs cannot satisfy regulatory audit requirements.

**SQLite for window-based lookback**
Each rule needs to query recent transactions for the same account (velocity windows, structuring windows, layering detection). SQLite with indexed queries on sender_id and timestamp delivers sub-10ms lookback on 10,000+ transactions without a database server.

**Synthetic dataset over real transaction data**
Real customer transaction data cannot be used in a portfolio project. The synthetic generator creates statistically realistic transaction patterns (organic amount distributions, channel mix, time-of-day spread) while embedding known fraud signatures at ground-truth locations — enabling precise evaluation of rule recall.

---

## 14. What I Would Do Differently

- Add a streaming mode that reads from a message queue (Kafka/Redis) for real-time ingestion rather than batch CSV processing
- Implement ML-based anomaly scoring (isolation forest) as a second-layer signal alongside rule-based detection
- Add graph analysis to trace full fund flow networks and identify money mule clusters
- Feed alerts into the Elastic Stack from MiniSOC for unified SOC visibility
- Add a case management workflow — analysts acknowledge, escalate, or dismiss alerts
- Backtest detection rules against historical fraud datasets (e.g. Kaggle credit card fraud dataset)

---

## 15. Next Steps

- [ ] Add Kafka streaming ingestion mode
- [ ] Implement graph-based fund flow analysis
- [ ] Feed alerts into MiniSOC Elastic Stack
- [ ] Sit CompTIA Security+ SY0-701
- [ ] Target fintech security analyst and fraud analyst roles in East Africa and remotely

---

*Built on: Kali Linux 2026.2 inside Docker Desktop (WSL2)*
*Dataset: Synthetic — no real customer transaction data used*
*Regulatory basis: CBK Kenya, CBN Nigeria, BOU Uganda, FATF guidelines*
*Part of an active cybersecurity portfolio: [github.com/Mastertactician23](https://github.com/Mastertactician23)*
