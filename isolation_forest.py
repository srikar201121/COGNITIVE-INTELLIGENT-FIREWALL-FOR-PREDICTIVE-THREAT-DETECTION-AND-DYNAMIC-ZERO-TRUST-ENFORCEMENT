from sklearn.ensemble import IsolationForest
import pandas as pd
import warnings
warnings.filterwarnings('ignore') # Prevent warnings during prediction
from state_tracker import firewall_state

def train_model(baseline_data):
    """
    Trains the Isolation Forest model on a baseline dataset (e.g. synthetic data)
    """
    df = pd.DataFrame(baseline_data)
    
    # We only care about TCP/UDP
    df = df[df["protocol"].isin(["TCP", "UDP"])]
    df["protocol_encoded"] = df["protocol"].map({"TCP": 0, "UDP": 1})
    
    # During synthetic training, we assume a synthetic normal packet rate
    # Let's say all normal synthetic traffic has a rate of 1.0 pps
    if "packet_rate" not in df.columns:
        df["packet_rate"] = 1.0
    
    # Advanced Model: Using protocol, port, size AND packet_rate
    features = df[["protocol_encoded", "port", "packet_size", "packet_rate"]]
    
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    model.fit(features)
    return model

def predict_anomalies(model, traffic_data):
    """
    Predicts anomalies on new data using a pre-trained model.
    Now leverages stateful packet rate tracking!
    """
    df = pd.DataFrame(traffic_data)
    
    # Handle empty frames
    if df.empty:
        return df
        
    # Keep only TCP/UDP for prediction since that's what we trained on
    df = df[df["protocol"].isin(["TCP", "UDP"])]
    
    if df.empty:
        return df

    df["protocol_encoded"] = df["protocol"].map({"TCP": 0, "UDP": 1})
    
    # Calculate stateful packet rate for each IP
    rates = []
    for ip in df["src_ip"]:
        # We record the packet in the global firewall state tracker
        rates.append(firewall_state.record_packet(ip))
        
    df["packet_rate"] = rates
    
    # Predict using the 4 features
    features = df[["protocol_encoded", "port", "packet_size", "packet_rate"]]
    
    df["anomaly"] = model.predict(features)
    df["anomaly_score"] = model.decision_function(features)
    
    return df

# For backward compatibility with things expecting the old logic directly
def detect_anomalies(traffic_data):
    model = train_model(traffic_data)
    return predict_anomalies(model, traffic_data), model
