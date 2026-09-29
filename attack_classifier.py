from sklearn.ensemble import RandomForestClassifier
import pandas as pd

# Global model
model = RandomForestClassifier()

# Flag to track training
model_trained = False


def train_classifier(data):

    global model_trained

    df = pd.DataFrame(data)

    if df.empty:
        return

    # encode protocol
    df["protocol_encoded"] = df["protocol"].map({"TCP": 0, "UDP": 1}).fillna(0)

    X = df[["protocol_encoded", "port", "packet_size"]]

    # dummy labels (normal traffic)
    y = [0] * len(df)

    model.fit(X, y)

    model_trained = True


def classify_attack(row):

    global model_trained

    # If model not trained yet
    if not model_trained:
        return "UNKNOWN"

    protocol = 0 if row["protocol"] == "TCP" else 1

    X = [[protocol, row["port"], row["packet_size"]]]

    pred = model.predict(X)[0]

    if pred == 1:
        return "ATTACK"

    return "NORMAL"
