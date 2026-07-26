#!/usr/bin/env python3
"""
Transaction Anomaly Detection Engine
Author: Kofi Asibey-Kitiabi
Description: Real-time financial transaction anomaly detection system targeting
             fraud patterns documented in East African fintech environments.
             Implements rule-based detection + statistical scoring to identify
             velocity attacks, layered transfers, SIM-swap post-compromise
             disbursements, structuring, and account takeover patterns.
             Produces colour-coded terminal alerts and an HTML risk report.
GitHub: https://github.com/Mastertactician23/transaction-anomaly-detector
Sources: CBK Fraud Report 2025, CA Kenya Q1/Q2 2025, INTERPOL Africa 2025
"""

import json
import csv
import os
import sys
import sqlite3
import hashlib
import argparse
import random
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLOUR = True
except ImportError:
    COLOUR = False

def red(t):     return Fore.RED + t + Style.RESET_ALL if COLOUR else t
def green(t):   return Fore.GREEN + t + Style.RESET_ALL if COLOUR else t
def yellow(t):  return Fore.YELLOW + t + Style.RESET_ALL if COLOUR else t
def cyan(t):    return Fore.CYAN + t + Style.RESET_ALL if COLOUR else t
def magenta(t): return Fore.MAGENTA + t + Style.RESET_ALL if COLOUR else t
def bold(t):    return Style.BRIGHT + t + Style.RESET_ALL if COLOUR else t


# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────

CONFIG = {
    "db_path": "/opt/txn-monitor/transactions.db",
    "log_path": "/opt/txn-monitor/alerts.json",
    "report_path": "/opt/txn-monitor/reports",

    # Velocity thresholds
    "velocity_txn_count_1min": 5,       # >5 txns in 60s = suspicious
    "velocity_txn_count_5min": 15,      # >15 txns in 5min = suspicious
    "velocity_amount_1hr_kes": 500000,  # >KES 500k in 1hr = suspicious

    # Amount thresholds
    "large_txn_kes": 100000,            # CBK reporting threshold
    "structuring_below_kes": 100000,    # Structuring: just below threshold
    "structuring_window_minutes": 60,   # Multiple txns in window
    "structuring_count": 3,             # Min txns to flag structuring

    # Round amount thresholds
    "round_amount_multiples": [
        10000, 20000, 50000, 100000,
        200000, 500000, 1000000
    ],

    # Geo/time thresholds
    "impossible_travel_minutes": 30,    # Two countries within 30 min
    "night_hours": (23, 5),             # 11PM - 5AM EAT

    # Account risk
    "new_account_days": 30,             # Account < 30 days old
    "dormant_account_days": 90,         # No activity for 90 days

    # Layering thresholds
    "layering_hop_count": 3,            # Funds move through 3+ accounts
    "layering_time_window_minutes": 120,
}

# Risk score weights per rule
RULE_WEIGHTS = {
    "VELOCITY_COUNT":           25,
    "VELOCITY_AMOUNT":          20,
    "STRUCTURING":              30,
    "ROUND_AMOUNT":             10,
    "NIGHT_TRANSACTION":        10,
    "NEW_ACCOUNT_LARGE_TXN":    25,
    "DORMANT_ACCOUNT_REVIVAL":  20,
    "CROSS_BORDER_RAPID":       25,
    "LAYERING_PATTERN":         35,
    "REFUND_ABUSE":             20,
    "ROUND_TRIP":               30,
    "SIM_SWAP_PATTERN":         40,
    "HIGH_RISK_CORRIDOR":       15,
    "MULE_ACCOUNT_PATTERN":     35,
}

# High-risk transaction corridors documented in East Africa
HIGH_RISK_CORRIDORS = [
    ("KE", "NG"), ("NG", "KE"),  # Kenya-Nigeria corridor
    ("KE", "SO"), ("SO", "KE"),  # Kenya-Somalia corridor (hawala)
    ("UG", "CD"), ("CD", "UG"),  # Uganda-DRC corridor
    ("TZ", "NG"), ("NG", "TZ"),  # Tanzania-Nigeria
]


# ──────────────────────────────────────────────
# DATABASE
# ──────────────────────────────────────────────

class TransactionDB:
    def __init__(self, db_path=CONFIG["db_path"]):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init()

    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self):
        conn = self._conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS transactions (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount_kes REAL NOT NULL,
                channel TEXT,
                sender_country TEXT DEFAULT 'KE',
                receiver_country TEXT DEFAULT 'KE',
                txn_type TEXT,
                reference TEXT,
                account_age_days INTEGER DEFAULT 365,
                last_activity_days INTEGER DEFAULT 0,
                ingested_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                txn_id TEXT,
                rule TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                detail TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS account_profiles (
                account_id TEXT PRIMARY KEY,
                total_txn_count INTEGER DEFAULT 0,
                total_amount_kes REAL DEFAULT 0,
                avg_txn_kes REAL DEFAULT 0,
                last_seen TEXT,
                risk_score INTEGER DEFAULT 0,
                flags TEXT DEFAULT '[]'
            );
            CREATE INDEX IF NOT EXISTS idx_txn_sender ON transactions(sender_id);
            CREATE INDEX IF NOT EXISTS idx_txn_time ON transactions(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
        """)
        conn.commit()
        conn.close()

    def insert_transaction(self, txn: dict):
        conn = self._conn()
        conn.execute("""
            INSERT OR REPLACE INTO transactions
            (id, timestamp, sender_id, receiver_id, amount_kes,
             channel, sender_country, receiver_country, txn_type,
             reference, account_age_days, last_activity_days)
            VALUES (:id, :timestamp, :sender_id, :receiver_id, :amount_kes,
                    :channel, :sender_country, :receiver_country, :txn_type,
                    :reference, :account_age_days, :last_activity_days)
        """, txn)
        conn.commit()
        conn.close()

    def log_alert(self, txn_id, rule, severity, risk_score, detail):
        conn = self._conn()
        conn.execute("""
            INSERT INTO alerts (txn_id, rule, severity, risk_score, detail)
            VALUES (?, ?, ?, ?, ?)
        """, (txn_id, rule, severity, risk_score, detail))
        conn.commit()
        conn.close()

    def get_recent_txns(self, sender_id, minutes=60):
        cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat()
        conn = self._conn()
        rows = conn.execute("""
            SELECT * FROM transactions
            WHERE sender_id=? AND timestamp > ?
            ORDER BY timestamp DESC
        """, (sender_id, cutoff)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_txns_between(self, sender_id, receiver_id, minutes=120):
        cutoff = (datetime.now() - timedelta(minutes=minutes)).isoformat()
        conn = self._conn()
        rows = conn.execute("""
            SELECT * FROM transactions
            WHERE (sender_id=? AND receiver_id=?) OR
                  (sender_id=? AND receiver_id=?)
            AND timestamp > ?
            ORDER BY timestamp
        """, (sender_id, receiver_id, receiver_id, sender_id, cutoff)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_all_alerts(self, limit=200):
        conn = self._conn()
        rows = conn.execute("""
            SELECT a.*, t.amount_kes, t.sender_id, t.receiver_id,
                   t.channel, t.txn_type
            FROM alerts a
            LEFT JOIN transactions t ON a.txn_id = t.id
            ORDER BY a.timestamp DESC LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_stats(self):
        conn = self._conn()
        total = conn.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
        alerted = conn.execute(
            "SELECT COUNT(DISTINCT txn_id) FROM alerts"
        ).fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'"
        ).fetchone()[0]
        high = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity='HIGH'"
        ).fetchone()[0]
        total_volume = conn.execute(
            "SELECT COALESCE(SUM(amount_kes),0) FROM transactions"
        ).fetchone()[0]
        conn.close()
        return {
            "total_transactions": total,
            "flagged_transactions": alerted,
            "critical_alerts": critical,
            "high_alerts": high,
            "total_volume_kes": total_volume,
            "flag_rate_pct": round((alerted/total*100) if total > 0 else 0, 2)
        }


# ──────────────────────────────────────────────
# DETECTION RULES
# ──────────────────────────────────────────────

class AnomalyDetector:
    def __init__(self, db: TransactionDB):
        self.db = db

    def _alert(self, txn, rule, severity, detail):
        score = RULE_WEIGHTS.get(rule, 10)
        self.db.log_alert(txn["id"], rule, severity, score, detail)
        return {
            "rule": rule,
            "severity": severity,
            "score": score,
            "detail": detail
        }

    def check_velocity(self, txn):
        """
        RULE: Velocity Attack
        Pattern: Rapid succession of transactions from same sender.
        East Africa context: Carbanak/FIN7 techniques documented in
        Kenya and Uganda use velocity attacks to drain accounts before
        fraud detection triggers. CBK mandates velocity monitoring.
        """
        alerts = []
        recent_1min = self.db.get_recent_txns(txn["sender_id"], minutes=1)
        recent_5min = self.db.get_recent_txns(txn["sender_id"], minutes=5)
        recent_1hr = self.db.get_recent_txns(txn["sender_id"], minutes=60)

        if len(recent_1min) >= CONFIG["velocity_txn_count_1min"]:
            alerts.append(self._alert(
                txn, "VELOCITY_COUNT", "CRITICAL",
                f"{len(recent_1min)} transactions in 60 seconds from "
                f"{txn['sender_id']} — likely automated attack"
            ))

        elif len(recent_5min) >= CONFIG["velocity_txn_count_5min"]:
            alerts.append(self._alert(
                txn, "VELOCITY_COUNT", "HIGH",
                f"{len(recent_5min)} transactions in 5 minutes from "
                f"{txn['sender_id']}"
            ))

        hr_total = sum(r["amount_kes"] for r in recent_1hr)
        if hr_total > CONFIG["velocity_amount_1hr_kes"]:
            alerts.append(self._alert(
                txn, "VELOCITY_AMOUNT", "HIGH",
                f"KES {hr_total:,.0f} transacted in 1 hour from "
                f"{txn['sender_id']} (threshold: "
                f"KES {CONFIG['velocity_amount_1hr_kes']:,.0f})"
            ))

        return alerts

    def check_structuring(self, txn):
        """
        RULE: Structuring / Smurfing
        Pattern: Multiple transactions just below CBK reporting threshold
        of KES 100,000 to avoid detection.
        East Africa context: Documented in Flutterwave breach — layered
        transfers split across accounts to stay under per-institution
        monitoring thresholds.
        """
        alerts = []
        threshold = CONFIG["large_txn_kes"]
        if txn["amount_kes"] < threshold and txn["amount_kes"] > threshold * 0.7:
            recent = self.db.get_recent_txns(
                txn["sender_id"],
                minutes=CONFIG["structuring_window_minutes"]
            )
            near_threshold = [
                r for r in recent
                if r["amount_kes"] < threshold and r["amount_kes"] > threshold * 0.7
            ]
            if len(near_threshold) >= CONFIG["structuring_count"]:
                total = sum(r["amount_kes"] for r in near_threshold)
                alerts.append(self._alert(
                    txn, "STRUCTURING", "CRITICAL",
                    f"{len(near_threshold)} transactions between "
                    f"KES {threshold*0.7:,.0f}–{threshold:,.0f} "
                    f"within {CONFIG['structuring_window_minutes']}min. "
                    f"Total: KES {total:,.0f}. Classic structuring pattern."
                ))
        return alerts

    def check_round_amount(self, txn):
        """
        RULE: Suspicious Round Amount
        Pattern: Exact round amounts are statistically unusual in organic
        transactions and often indicate manual fraud setup.
        """
        alerts = []
        for multiple in CONFIG["round_amount_multiples"]:
            if txn["amount_kes"] == multiple:
                severity = "HIGH" if multiple >= 100000 else "MEDIUM"
                alerts.append(self._alert(
                    txn, "ROUND_AMOUNT", severity,
                    f"Exact round amount: KES {multiple:,.0f}. "
                    f"Statistically unusual — possible manual fraud setup."
                ))
                break
        return alerts

    def check_night_transaction(self, txn):
        """
        RULE: Night-time Large Transaction
        Pattern: Large transactions between 11PM-5AM EAT are high-risk.
        East Africa context: SIM-swap attacks are typically executed
        between midnight and 4AM when victims are asleep and unable to
        notice OTP messages or account changes.
        """
        alerts = []
        try:
            ts = datetime.fromisoformat(txn["timestamp"])
            hour = ts.hour
            night_start, night_end = CONFIG["night_hours"]
            is_night = hour >= night_start or hour <= night_end
            if is_night and txn["amount_kes"] >= 50000:
                alerts.append(self._alert(
                    txn, "NIGHT_TRANSACTION", "HIGH",
                    f"KES {txn['amount_kes']:,.0f} transacted at "
                    f"{ts.strftime('%H:%M')} EAT. Large night-time "
                    f"transactions are a SIM-swap fraud indicator."
                ))
        except Exception:
            pass
        return alerts

    def check_new_account(self, txn):
        """
        RULE: New Account Large Transaction
        Pattern: Account opened recently initiating large transfer.
        East Africa context: KYC bypass scripts and synthetic identity
        fraud (documented in FIM tests) create accounts for immediate
        large-scale fraud. CBK Kenya flags accounts < 30 days old
        with large outgoing transfers.
        """
        alerts = []
        age = txn.get("account_age_days", 365)
        if age <= CONFIG["new_account_days"] and \
           txn["amount_kes"] >= CONFIG["large_txn_kes"]:
            alerts.append(self._alert(
                txn, "NEW_ACCOUNT_LARGE_TXN", "CRITICAL",
                f"Account {txn['sender_id']} is {age} days old and "
                f"initiating KES {txn['amount_kes']:,.0f} transfer. "
                f"Matches synthetic identity fraud pattern."
            ))
        return alerts

    def check_dormant_account(self, txn):
        """
        RULE: Dormant Account Sudden Activity
        Pattern: Account with no activity for 90+ days suddenly sends
        large transfer — classic account takeover indicator.
        East Africa context: Credential phishing campaigns targeting
        M-Pesa users result in dormant account takeovers followed by
        immediate full-balance withdrawal.
        """
        alerts = []
        dormant = txn.get("last_activity_days", 0)
        if dormant >= CONFIG["dormant_account_days"] and \
           txn["amount_kes"] >= 10000:
            alerts.append(self._alert(
                txn, "DORMANT_ACCOUNT_REVIVAL", "HIGH",
                f"Account {txn['sender_id']} had no activity for "
                f"{dormant} days. Sudden KES {txn['amount_kes']:,.0f} "
                f"outgoing — possible account takeover via phishing."
            ))
        return alerts

    def check_cross_border(self, txn):
        """
        RULE: High-Risk Cross-Border Corridor
        Pattern: Transaction between documented high-risk country pairs.
        East Africa context: Kenya-Nigeria, Kenya-Somalia corridors are
        flagged by INTERPOL Africa and used by syndicate money flows.
        FATF grey-list monitoring requires enhanced due diligence.
        """
        alerts = []
        corridor = (
            txn.get("sender_country", "KE"),
            txn.get("receiver_country", "KE")
        )
        if corridor in HIGH_RISK_CORRIDORS:
            alerts.append(self._alert(
                txn, "HIGH_RISK_CORRIDOR", "HIGH",
                f"Transaction on high-risk corridor: "
                f"{corridor[0]} → {corridor[1]}. "
                f"Enhanced due diligence required per FATF guidelines."
            ))

        if corridor[0] != corridor[1] and txn["amount_kes"] >= 50000:
            alerts.append(self._alert(
                txn, "CROSS_BORDER_RAPID", "MEDIUM",
                f"Cross-border transfer KES {txn['amount_kes']:,.0f}: "
                f"{corridor[0]} → {corridor[1]}."
            ))
        return alerts

    def check_layering(self, txn):
        """
        RULE: Layering / Fund Hop Pattern
        Pattern: Funds received then immediately re-transmitted.
        East Africa context: Flutterwave-style layered transfer chains
        distribute stolen funds across 3-4 accounts within 2 hours to
        evade per-institution monitoring. Uganda Pegasus breach used
        this technique with 2,000 SIM cards.
        """
        alerts = []
        window = CONFIG["layering_time_window_minutes"]
        # Check if sender recently received funds they are now forwarding
        recent_received = self.db.get_recent_txns(
            txn["receiver_id"], minutes=window
        )
        # Look for rapid re-transmission pattern
        received_as_sender = [
            r for r in recent_received
            if r["sender_id"] != txn["sender_id"]
        ]
        if len(received_as_sender) >= 2 and txn["amount_kes"] >= 10000:
            alerts.append(self._alert(
                txn, "LAYERING_PATTERN", "CRITICAL",
                f"Account {txn['receiver_id']} received funds from "
                f"{len(received_as_sender)} sources in last {window}min "
                f"and is now forwarding KES {txn['amount_kes']:,.0f}. "
                f"Classic layering/fund-hop pattern."
            ))
        return alerts

    def check_round_trip(self, txn):
        """
        RULE: Round-Trip Transaction
        Pattern: Funds sent to account that immediately sends back.
        Indicates fictitious transaction to create paper trail or
        test account access before larger fraud.
        """
        alerts = []
        recent = self.db.get_txns_between(
            txn["sender_id"], txn["receiver_id"], minutes=30
        )
        outgoing = [r for r in recent if r["sender_id"] == txn["sender_id"]]
        incoming = [r for r in recent if r["receiver_id"] == txn["sender_id"]]
        if outgoing and incoming:
            alerts.append(self._alert(
                txn, "ROUND_TRIP", "HIGH",
                f"Round-trip detected between {txn['sender_id']} and "
                f"{txn['receiver_id']} within 30 minutes. "
                f"Possible fictitious transaction or account test."
            ))
        return alerts

    def check_sim_swap(self, txn):
        """
        RULE: SIM-Swap Post-Compromise Pattern
        Pattern: Combination of new channel + night time + large amount
        + new device (channel change) on same account.
        East Africa context: SIM-swap fraud surged 87% in Kenya.
        Post-swap, attacker immediately initiates large B2C transfer.
        Combination of channel change + night + large amount is the
        documented attack sequence.
        """
        alerts = []
        try:
            ts = datetime.fromisoformat(txn["timestamp"])
            hour = ts.hour
            night_start, night_end = CONFIG["night_hours"]
            is_night = hour >= night_start or hour <= night_end
        except Exception:
            is_night = False

        is_large = txn["amount_kes"] >= 50000
        is_mobile = txn.get("channel", "").lower() in [
            "mpesa", "mobile", "ussd", "airtel_money"
        ]
        is_dormant = txn.get("last_activity_days", 0) >= 7

        if is_night and is_large and is_mobile and is_dormant:
            alerts.append(self._alert(
                txn, "SIM_SWAP_PATTERN", "CRITICAL",
                f"SIM-swap fraud pattern detected on {txn['sender_id']}: "
                f"night-time ({ts.strftime('%H:%M') if not isinstance(ts, str) else 'N/A'} EAT) "
                f"+ mobile channel + KES {txn['amount_kes']:,.0f} "
                f"+ account dormant {txn.get('last_activity_days',0)} days. "
                f"All four SIM-swap indicators present."
            ))
        return alerts

    def check_mule_pattern(self, txn):
        """
        RULE: Money Mule Account Pattern
        Pattern: Account receives from many senders then forwards bulk.
        East Africa context: Insider threat and SIM-swap operations use
        mule accounts that aggregate stolen funds before converting to
        crypto or cash. CBK fraud reports identify mule networks as
        primary laundering vehicle.
        """
        alerts = []
        recent = self.db.get_recent_txns(txn["receiver_id"], minutes=240)
        unique_senders = len(set(r["sender_id"] for r in recent))
        total_received = sum(r["amount_kes"] for r in recent)

        if unique_senders >= 5 and total_received >= 200000:
            alerts.append(self._alert(
                txn, "MULE_ACCOUNT_PATTERN", "CRITICAL",
                f"Account {txn['receiver_id']} received from "
                f"{unique_senders} unique senders in 4 hours, "
                f"total KES {total_received:,.0f}. "
                f"Matches money mule aggregation pattern."
            ))
        return alerts

    def analyse(self, txn: dict) -> list:
        """Run all detection rules against a transaction."""
        all_alerts = []
        all_alerts += self.check_velocity(txn)
        all_alerts += self.check_structuring(txn)
        all_alerts += self.check_round_amount(txn)
        all_alerts += self.check_night_transaction(txn)
        all_alerts += self.check_new_account(txn)
        all_alerts += self.check_dormant_account(txn)
        all_alerts += self.check_cross_border(txn)
        all_alerts += self.check_layering(txn)
        all_alerts += self.check_round_trip(txn)
        all_alerts += self.check_sim_swap(txn)
        all_alerts += self.check_mule_pattern(txn)
        return all_alerts


# ──────────────────────────────────────────────
# RISK SCORER
# ──────────────────────────────────────────────

def calculate_risk_score(alerts: list) -> tuple:
    """Aggregate risk score from all alerts on a transaction."""
    if not alerts:
        return 0, "LOW"
    total = min(sum(a["score"] for a in alerts), 100)
    severity = (
        "CRITICAL" if total >= 70 else
        "HIGH"     if total >= 40 else
        "MEDIUM"   if total >= 20 else
        "LOW"
    )
    return total, severity


# ──────────────────────────────────────────────
# CONSOLE ALERTER
# ──────────────────────────────────────────────

SEVERITY_COLOR = {
    "CRITICAL": red,
    "HIGH":     yellow,
    "MEDIUM":   cyan,
    "LOW":      green,
}
SEVERITY_SYMBOL = {
    "CRITICAL": "[!!!]",
    "HIGH":     "[!! ]",
    "MEDIUM":   "[ ! ]",
    "LOW":      "[ i ]",
}


def print_alert(txn: dict, alerts: list, score: int, severity: str):
    color = SEVERITY_COLOR.get(severity, cyan)
    sym = SEVERITY_SYMBOL.get(severity, "[ ? ]")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(color(f"\n{'─'*65}"))
    print(color(f"{sym} {severity} | Risk Score: {score}/100 | {ts}"))
    print(color(f"  TXN ID : {txn['id']}"))
    print(color(f"  Sender : {txn['sender_id']} → {txn['receiver_id']}"))
    print(color(f"  Amount : KES {txn['amount_kes']:,.0f}"))
    print(color(f"  Channel: {txn.get('channel','N/A')} | "
                f"Type: {txn.get('txn_type','N/A')}"))
    for a in alerts:
        a_color = SEVERITY_COLOR.get(a["severity"], cyan)
        print(a_color(f"  RULE   : [{a['rule']}] {a['detail'][:80]}"))
    print(color(f"{'─'*65}"))


# ──────────────────────────────────────────────
# HTML REPORT GENERATOR
# ──────────────────────────────────────────────

def generate_html_report(db: TransactionDB, output_path: str):
    stats = db.get_stats()
    alerts = db.get_all_alerts(limit=200)

    flag_rate_color = (
        "#f85149" if stats["flag_rate_pct"] > 10 else
        "#d29922" if stats["flag_rate_pct"] > 5 else
        "#3fb950"
    )

    severity_colors = {
        "CRITICAL": "#f85149",
        "HIGH":     "#d29922",
        "MEDIUM":   "#388bfd",
        "LOW":      "#3fb950",
    }

    alerts_html = ""
    for a in alerts:
        sc = severity_colors.get(a.get("severity", "LOW"), "#8b949e")
        alerts_html += f"""
        <tr>
          <td>{a.get('timestamp','')[:19]}</td>
          <td><span style="color:{sc};font-weight:600">
              {a.get('severity','')}</span></td>
          <td style="font-family:monospace;font-size:11px">
              {a.get('rule','')}</td>
          <td>{a.get('sender_id','N/A')}</td>
          <td>{a.get('receiver_id','N/A')}</td>
          <td>KES {float(a.get('amount_kes') or 0):,.0f}</td>
          <td style="font-size:11px">{str(a.get('detail',''))[:80]}</td>
          <td><span style="background:{sc}20;color:{sc};
              padding:2px 6px;border-radius:10px;font-size:11px">
              {a.get('risk_score',0)}</span></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Transaction Anomaly Report</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;color:#e6edf3;
     font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     font-size:14px}}
header{{background:#161b22;border-bottom:1px solid #21262d;
        padding:20px 32px}}
h1{{font-size:19px;font-weight:600;color:#58a6ff;margin-bottom:4px}}
.sub{{font-size:12px;color:#8b949e}}
main{{max-width:1300px;margin:0 auto;padding:24px 32px}}
.stats{{display:grid;grid-template-columns:repeat(6,1fr);
        gap:10px;margin-bottom:22px}}
.stat{{background:#161b22;border:1px solid #21262d;border-radius:8px;
       padding:14px;text-align:center}}
.val{{font-size:22px;font-weight:600;margin-bottom:2px}}
.lbl{{font-size:11px;color:#8b949e;text-transform:uppercase}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;
       padding:16px;margin-bottom:16px}}
h2{{font-size:13px;font-weight:600;color:#c9d1d9;margin-bottom:12px;
    padding-bottom:8px;border-bottom:1px solid #21262d}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
th{{text-align:left;padding:6px 10px;color:#8b949e;font-size:11px;
    text-transform:uppercase;border-bottom:1px solid #21262d}}
td{{padding:7px 10px;border-bottom:1px solid #0d1117;
    color:#c9d1d9;word-break:break-word}}
tr:hover td{{background:#1c2128}}
footer{{text-align:center;padding:20px;color:#8b949e;
        font-size:12px;border-top:1px solid #21262d;margin-top:24px}}
</style></head><body>
<header>
  <h1>Transaction Anomaly Detection Report</h1>
  <div class="sub">Author: Kofi Asibey-Kitiabi &nbsp;|&nbsp;
  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp;
  East African Fintech Fraud Pattern Coverage</div>
</header>
<main>
  <div class="stats">
    <div class="stat">
      <div class="val" style="color:#58a6ff">
          {stats['total_transactions']:,}</div>
      <div class="lbl">Transactions</div></div>
    <div class="stat">
      <div class="val" style="color:#d29922">
          {stats['flagged_transactions']:,}</div>
      <div class="lbl">Flagged</div></div>
    <div class="stat">
      <div class="val" style="color:#f85149">
          {stats['critical_alerts']:,}</div>
      <div class="lbl">Critical</div></div>
    <div class="stat">
      <div class="val" style="color:#d29922">
          {stats['high_alerts']:,}</div>
      <div class="lbl">High</div></div>
    <div class="stat">
      <div class="val" style="color:#3fb950">
          KES {stats['total_volume_kes']:,.0f}</div>
      <div class="lbl">Volume</div></div>
    <div class="stat">
      <div class="val" style="color:{flag_rate_color}">
          {stats['flag_rate_pct']}%</div>
      <div class="lbl">Flag Rate</div></div>
  </div>
  <div class="card"><h2>Alert Log ({len(alerts)} alerts)</h2>
    <div style="overflow-x:auto"><table>
      <thead><tr>
        <th>Timestamp</th><th>Severity</th><th>Rule</th>
        <th>Sender</th><th>Receiver</th><th>Amount</th>
        <th>Detail</th><th>Score</th>
      </tr></thead>
      <tbody>{alerts_html}</tbody>
    </table></div>
  </div>
</main>
<footer>Transaction Anomaly Detection Engine &nbsp;|&nbsp;
github.com/Mastertactician23/transaction-anomaly-detector &nbsp;|&nbsp;
East African Fintech Fraud Pattern Coverage</footer>
</body></html>"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)
    return output_path


# ──────────────────────────────────────────────
# SYNTHETIC DATA GENERATOR
# ──────────────────────────────────────────────

def generate_test_dataset(output_path: str, n_clean: int = 200):
    """
    Generate a realistic East African fintech transaction dataset
    combining clean transactions and embedded fraud patterns.
    """
    channels = ["mpesa", "airtel_money", "equitel", "bank_transfer",
                "card", "ussd", "app"]
    txn_types = ["B2C", "C2B", "P2P", "PAYBILL", "BUY_GOODS",
                 "WITHDRAWAL", "DEPOSIT"]
    countries = ["KE", "UG", "TZ", "NG", "SO", "RW", "ET"]

    transactions = []
    base_time = datetime.now() - timedelta(hours=24)

    def make_id():
        return "TXN" + hashlib.md5(
            str(random.random()).encode()
        ).hexdigest()[:10].upper()

    def make_account(prefix="ACC"):
        return prefix + str(random.randint(10000, 99999))

    # Clean transactions
    for i in range(n_clean):
        ts = base_time + timedelta(minutes=random.randint(0, 1380))
        amount = random.choice([
            random.uniform(100, 5000),
            random.uniform(5000, 50000),
            random.uniform(50000, 95000),
        ])
        transactions.append({
            "id": make_id(),
            "timestamp": ts.isoformat(),
            "sender_id": make_account("KE"),
            "receiver_id": make_account("KE"),
            "amount_kes": round(amount, 2),
            "channel": random.choice(channels),
            "sender_country": "KE",
            "receiver_country": random.choice(["KE", "KE", "KE", "UG", "TZ"]),
            "txn_type": random.choice(txn_types),
            "reference": f"REF{random.randint(100000,999999)}",
            "account_age_days": random.randint(60, 1825),
            "last_activity_days": random.randint(0, 30),
        })

    # FRAUD SCENARIO 1: Velocity attack (automated draining)
    attacker = make_account("ATK")
    for i in range(8):
        ts = datetime.now() - timedelta(seconds=random.randint(0, 50))
        transactions.append({
            "id": make_id(),
            "timestamp": ts.isoformat(),
            "sender_id": attacker,
            "receiver_id": make_account("MUL"),
            "amount_kes": round(random.uniform(45000, 99000), 2),
            "channel": "mpesa",
            "sender_country": "KE",
            "receiver_country": "KE",
            "txn_type": "P2P",
            "reference": f"REF{random.randint(100000,999999)}",
            "account_age_days": random.randint(200, 500),
            "last_activity_days": 0,
        })

    # FRAUD SCENARIO 2: Structuring
    structurer = make_account("STR")
    for i in range(4):
        ts = datetime.now() - timedelta(minutes=random.randint(0, 45))
        transactions.append({
            "id": make_id(),
            "timestamp": ts.isoformat(),
            "sender_id": structurer,
            "receiver_id": make_account("REC"),
            "amount_kes": round(random.uniform(85000, 99500), 2),
            "channel": "bank_transfer",
            "sender_country": "KE",
            "receiver_country": "KE",
            "txn_type": "B2C",
            "reference": f"REF{random.randint(100000,999999)}",
            "account_age_days": 400,
            "last_activity_days": 2,
        })

    # FRAUD SCENARIO 3: SIM-swap pattern
    simswap_victim = make_account("VIC")
    ts = datetime.now().replace(hour=2, minute=15)
    transactions.append({
        "id": make_id(),
        "timestamp": ts.isoformat(),
        "sender_id": simswap_victim,
        "receiver_id": make_account("ATK"),
        "amount_kes": 150000.00,
        "channel": "mpesa",
        "sender_country": "KE",
        "receiver_country": "KE",
        "txn_type": "P2P",
        "reference": f"REF{random.randint(100000,999999)}",
        "account_age_days": 730,
        "last_activity_days": 14,
    })

    # FRAUD SCENARIO 4: High-risk corridor
    transactions.append({
        "id": make_id(),
        "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
        "sender_id": make_account("NG"),
        "receiver_id": make_account("KE"),
        "amount_kes": 500000.00,
        "channel": "bank_transfer",
        "sender_country": "NG",
        "receiver_country": "KE",
        "txn_type": "B2C",
        "reference": f"REF{random.randint(100000,999999)}",
        "account_age_days": 45,
        "last_activity_days": 0,
    })

    # FRAUD SCENARIO 5: New account large txn (synthetic identity)
    transactions.append({
        "id": make_id(),
        "timestamp": datetime.now().isoformat(),
        "sender_id": make_account("NEW"),
        "receiver_id": make_account("EXT"),
        "amount_kes": 250000.00,
        "channel": "app",
        "sender_country": "KE",
        "receiver_country": "UG",
        "txn_type": "B2C",
        "reference": f"REF{random.randint(100000,999999)}",
        "account_age_days": 3,
        "last_activity_days": 0,
    })

    # FRAUD SCENARIO 6: Round amounts (manual fraud setup)
    for amount in [50000, 100000, 200000]:
        transactions.append({
            "id": make_id(),
            "timestamp": (datetime.now() -
                          timedelta(minutes=random.randint(10, 120))).isoformat(),
            "sender_id": make_account("RND"),
            "receiver_id": make_account("MUL"),
            "amount_kes": float(amount),
            "channel": random.choice(channels),
            "sender_country": "KE",
            "receiver_country": "KE",
            "txn_type": "P2P",
            "reference": f"REF{random.randint(100000,999999)}",
            "account_age_days": 180,
            "last_activity_days": 5,
        })

    # FRAUD SCENARIO 7: Dormant account revival
    transactions.append({
        "id": make_id(),
        "timestamp": datetime.now().isoformat(),
        "sender_id": make_account("DRM"),
        "receiver_id": make_account("ATK"),
        "amount_kes": 85000.00,
        "channel": "mpesa",
        "sender_country": "KE",
        "receiver_country": "SO",
        "txn_type": "P2P",
        "reference": f"REF{random.randint(100000,999999)}",
        "account_age_days": 1200,
        "last_activity_days": 180,
    })

    # Write CSV
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    fieldnames = list(transactions[0].keys())
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(transactions)

    print(green(f"  [+] Generated {len(transactions)} transactions "
                f"({n_clean} clean + {len(transactions)-n_clean} fraud "
                f"scenarios) → {output_path}"))
    return output_path


# ──────────────────────────────────────────────
# MAIN PIPELINE
# ──────────────────────────────────────────────

def process_csv(csv_path: str, db: TransactionDB,
                detector: AnomalyDetector, verbose: bool = True):
    """Process a CSV file of transactions through the detection engine."""
    total = 0
    flagged = 0
    errors = 0

    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                txn = {
                    "id": row.get("id", ""),
                    "timestamp": row.get("timestamp", ""),
                    "sender_id": row.get("sender_id", ""),
                    "receiver_id": row.get("receiver_id", ""),
                    "amount_kes": float(row.get("amount_kes", 0)),
                    "channel": row.get("channel", ""),
                    "sender_country": row.get("sender_country", "KE"),
                    "receiver_country": row.get("receiver_country", "KE"),
                    "txn_type": row.get("txn_type", ""),
                    "reference": row.get("reference", ""),
                    "account_age_days": int(row.get("account_age_days", 365)),
                    "last_activity_days": int(row.get("last_activity_days", 0)),
                }
                db.insert_transaction(txn)
                alerts = detector.analyse(txn)
                total += 1

                if alerts:
                    flagged += 1
                    score, severity = calculate_risk_score(alerts)
                    if verbose:
                        print_alert(txn, alerts, score, severity)

            except Exception as e:
                errors += 1
                if verbose:
                    print(yellow(f"  [!] Error processing row: {e}"))

    return total, flagged, errors


def main():
    parser = argparse.ArgumentParser(
        description="Transaction Anomaly Detection Engine — East African Fintech"
    )
    parser.add_argument("--input", "-i",
                        help="CSV file of transactions to analyse")
    parser.add_argument("--generate", "-g", action="store_true",
                        help="Generate synthetic test dataset and analyse it")
    parser.add_argument("--report", "-r", action="store_true",
                        help="Generate HTML report after analysis")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress per-transaction console output")
    args = parser.parse_args()

    print("")
    print(bold(cyan("  ╔══════════════════════════════════════════════╗")))
    print(bold(cyan("  ║  TRANSACTION ANOMALY DETECTION ENGINE       ║")))
    print(bold(cyan("  ║  by Kofi Asibey-Kitiabi                     ║")))
    print(bold(cyan("  ╚══════════════════════════════════════════════╝")))
    print(f"  Rules    : {len(RULE_WEIGHTS)} detection rules")
    print(f"  Focus    : East African fintech fraud patterns")
    print(f"  Coverage : Velocity · Structuring · SIM-swap · Layering")
    print(f"             Mule accounts · KYC bypass · Cross-border")
    print("")

    db = TransactionDB()
    detector = AnomalyDetector(db)

    csv_path = None
    if args.generate:
        csv_path = "/opt/txn-monitor/test_transactions.csv"
        print(bold("  [*] Generating synthetic East African fintech dataset..."))
        generate_test_dataset(csv_path, n_clean=200)

    elif args.input:
        csv_path = args.input
        if not os.path.exists(csv_path):
            print(red(f"  [ERROR] File not found: {csv_path}"))
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(0)

    print(bold(f"\n  [*] Analysing transactions from {csv_path}..."))
    total, flagged, errors = process_csv(
        csv_path, db, detector, verbose=not args.quiet
    )

    stats = db.get_stats()
    print(bold(cyan(f"\n{'─'*60}")))
    print(bold("  ANALYSIS SUMMARY"))
    print(bold(cyan(f"{'─'*60}")))
    print(f"  Transactions analysed : {total}")
    print(f"  Flagged               : {flagged}")
    print(f"  Flag rate             : {stats['flag_rate_pct']}%")
    print(red(f"  Critical alerts       : {stats['critical_alerts']}"))
    print(yellow(f"  High alerts           : {stats['high_alerts']}"))
    print(f"  Total volume          : KES {stats['total_volume_kes']:,.0f}")
    print(f"  Errors                : {errors}")
    print("")

    if args.report:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = f"/opt/txn-monitor/reports/report_{ts}.html"
        generate_html_report(db, report_path)
        print(green(f"  [✓] HTML report: {report_path}"))
        print(cyan(f"  [*] Copy to Windows: docker cp ctf-solver:"
                   f"{report_path} C:\\soc-lab\\txn_report.html"))
    print("")


if __name__ == "__main__":
    main()
