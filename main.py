from isolation_forest import detect_anomalies
from risk_scoring import calculate_risk
from zero_trust_policy import apply_zero_trust_policy
from firewall_logger import log_firewall_action
from live_traffic import capture_live_traffic

traffic = capture_live_traffic(50)

results, model = detect_anomalies(traffic)

anomalies = results[results["anomaly"] == -1]
print("Detected Anomalies:")
print(anomalies.head())

results["risk_score"] = results["anomaly_score"].apply(
    lambda x: calculate_risk(x)[0]
)

results["risk_level"] = results["anomaly_score"].apply(
    lambda x: calculate_risk(x)[1]
)

results["policy_action"] = results.apply(
    lambda row: apply_zero_trust_policy(row["risk_level"], row["src_ip"]),
    axis=1
)

firewall_logs = []

for _, row in results.iterrows():
    firewall_logs.append(log_firewall_action(row))

print("\nRecent Firewall Logs:")
for log in firewall_logs[:5]:
    print(log)
