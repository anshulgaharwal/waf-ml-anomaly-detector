import pandas as pd
import matplotlib.pyplot as plt
import joblib
import os
from sklearn.ensemble import IsolationForest

def load_data():
    df = pd.read_csv("./data/traffic_data.csv")
    return df

import os

def train_model(df):
    model_path = "models/isolation_forest.pkl"

    # If model already exists → load
    if os.path.exists(model_path):
        print("📌 Loaded existing trained model")
        model = joblib.load(model_path)
        return model

    # Else train new model
    print("⚙️ Training new model...")
    model = IsolationForest(contamination=0.15, random_state=42)
    model.fit(df)

    joblib.dump(model, model_path)
    print("💾 Model saved successfully")

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

def visualize_results(df):
    plt.figure(figsize=(10,5))

    normal = df[df["anomaly"] == 1]
    anomaly = df[df["anomaly"] == -1]

    plt.plot(normal["requests_per_min"], label="Normal Traffic", marker='o')

    plt.plot(anomaly["requests_per_min"], 'ro', label="Anomaly")

    plt.title("Network Traffic Anomaly Detection")
    plt.xlabel("Time / Request Index")
    plt.ylabel("Requests Per Minute")
    plt.legend()
    plt.grid(True)
    plt.show()


if __name__ == "__main__":
    df = load_data()
    model = train_model(df)
    result = detect_anomalies(model, df)
    print(result)
    visualize_results(result)
