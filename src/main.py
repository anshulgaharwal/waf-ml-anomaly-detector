import pandas as pd
from sklearn.ensemble import IsolationForest

def load_data():
    data = {
        "requests_per_min": [10, 12, 11, 9, 8, 300, 10, 11, 12],
        "avg_payload_size": [400, 420, 430, 410, 415, 2000, 405, 410, 420],
        "unique_ips": [2, 2, 3, 2, 2, 20, 2, 2, 3]
    }

    df = pd.DataFrame(data)
    return df

def train_model(df):
    model = IsolationForest(contamination=0.15, random_state=42)
    model.fit(df)
    return model

def detect_anomalies(model, df):
    predictions = model.predict(df)
    df["anomaly"] = predictions
    
    for index, row in df.iterrows():
        if row["anomaly"] == -1:
            print("\n🚨 ALERT: Suspicious Traffic Detected 🚨")
            print(f"Requests/min      : {row['requests_per_min']}")
            print(f"Avg Payload Size  : {row['avg_payload_size']}")
            print(f"Unique IPs        : {row['unique_ips']}")
            
            # Simple Reasoning
            reasons = []
            if row["requests_per_min"] > 100:
                reasons.append("Unusual traffic spike")
            if row["avg_payload_size"] > 1000:
                reasons.append("Large payload anomaly")
            if row["unique_ips"] > 5:
                reasons.append("Abnormal IP activity")
            
            if reasons:
                print("Reason(s):", ", ".join(reasons))
            else:
                print("Reason: Unusual behavioral deviation")
    
    return df


if __name__ == "__main__":
    df = load_data()
    model = train_model(df)
    result = detect_anomalies(model, df)
    print(result)
