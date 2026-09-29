from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd

from isolation_forest import train_model, predict_anomalies
from risk_scoring import calculate_risk
from zero_trust_policy import apply_zero_trust_policy
from firewall_logger import log_firewall_action
from live_traffic import capture_live_traffic
from state_tracker import firewall_state

from attack_detection import detect_attack
from attack_classifier import classify_attack, train_classifier


app = FastAPI(title="Intelligent AI Firewall")

# Enable CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------
# Train baseline ML models at startup
# ------------------------------------------------

print("Capturing baseline traffic for training...")

baseline_data = capture_live_traffic(20)

if baseline_data:

    print("Training anomaly detection model...")
    global_model = train_model(baseline_data)

    print("Training attack classifier...")
    train_classifier(baseline_data)

else:

    print("No baseline traffic captured. Model not trained.")
    global_model = None


# ------------------------------------------------
# MAIN DASHBOARD API
# ------------------------------------------------

@app.get("/live-dashboard")
def live_dashboard():

    traffic = capture_live_traffic(30)

    if not traffic or global_model is None:

        return {
            "total_traffic": 0,
            "blocked_count": 0,
            "logs": [],
            "banned_ips": firewall_state.get_banned_ips(),
            "attack_summary": {}
        }

    # Convert to dataframe
    results = predict_anomalies(global_model, traffic)

    if results.empty:

        return {
            "total_traffic": 0,
            "blocked_count": 0,
            "logs": [],
            "banned_ips": firewall_state.get_banned_ips(),
            "attack_summary": {}
        }

    # ------------------------------------------------
    # Risk scoring
    # ------------------------------------------------

    results["risk_score"] = results["anomaly_score"].apply(
        lambda x: calculate_risk(x)[0]
    )

    results["risk_level"] = results["anomaly_score"].apply(
        lambda x: calculate_risk(x)[1]
    )

    # ------------------------------------------------
    # Attack detection
    # ------------------------------------------------

    results["attack_type"] = results.apply(
        lambda row: detect_attack(row),
        axis=1
    )

    # ------------------------------------------------
    # AI classification
    # ------------------------------------------------

    results["ai_classification"] = results.apply(
        lambda row: classify_attack(row),
        axis=1
    )

    # ------------------------------------------------
    # Zero Trust firewall enforcement
    # ------------------------------------------------

    results["policy_action"] = results.apply(
        lambda row: apply_zero_trust_policy(row["risk_level"], row["src_ip"]),
        axis=1
    )

    # ------------------------------------------------
    # Logging
    # ------------------------------------------------

    logs = []

    for _, row in results.iterrows():

        log = log_firewall_action(row)

        log["attack_type"] = row["attack_type"]
        log["ai_classification"] = row["ai_classification"]

        logs.append(log)

    # Count blocked
    blocked = len(
        results[results["policy_action"].str.contains("BLOCK", case=False)]
    )

    # Attack summary
    attack_summary = results["attack_type"].value_counts().to_dict()

    return {

        "total_traffic": len(results),

        "blocked_count": blocked,

        "logs": logs[:25],

        "banned_ips": firewall_state.get_banned_ips(),

        "attack_summary": attack_summary
    }


# ------------------------------------------------
# Simple traffic API
# ------------------------------------------------

@app.get("/traffic")
def get_traffic():

    traffic = capture_live_traffic(20)

    return {
        "traffic": traffic
    }


# ------------------------------------------------
# Basic firewall run endpoint
# ------------------------------------------------

@app.get("/run-firewall")
def run_firewall():

    traffic = capture_live_traffic(30)

    if not traffic or global_model is None:

        return {
            "message": "No traffic captured",
            "total_traffic": 0
        }

    results = predict_anomalies(global_model, traffic)

    return {
        "total_traffic": len(results)
    }
