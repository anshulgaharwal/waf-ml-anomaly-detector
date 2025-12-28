import pandas as pd
import matplotlib.pyplot as plt
import joblib
from datetime import datetime
import os
from sklearn.ensemble import IsolationForest

def load_data():
    df = pd.read_csv("./data/traffic_data.csv")
    return df

def analyze_statistics(df):
    print("\n📊 TRAFFIC BASELINE STATISTICS")
    print(df.describe())

def train_model(df):
    model_path = "models/isolation_forest.pkl"

    mean_requests = df["requests_per_min"].mean()
    std_requests = df["requests_per_min"].std()

    # Adaptive contamination
    if std_requests < 20:
        contamination = 0.05   # stable network → strict
    elif std_requests < 60:
        contamination = 0.10   # moderately variable
    else:
        contamination = 0.15   # very dynamic traffic

    print(f"\n🧠 Adaptive Contamination Selected: {contamination}")

    if os.path.exists(model_path):
        print("📌 Loaded existing trained model")
        model = joblib.load(model_path)
        return model

    print("⚙️ Training new adaptive model...")
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(df)

    joblib.dump(model, model_path)
    print("💾 Model saved successfully")

    return model

def calculate_severity(row):
    score = 0

    # Weight logic
    if row["requests_per_min"] > 100:
        score += 3
    elif row["requests_per_min"] > 50:
        score += 2

    if row["avg_payload_size"] > 1200:
        score += 3
    elif row["avg_payload_size"] > 800:
        score += 2

    if row["unique_ips"] > 10:
        score += 3
    elif row["unique_ips"] > 5:
        score += 2

    # Convert to label
    if score >= 7:
        return "CRITICAL"
    elif score >= 4:
        return "MODERATE"
    else:
        return "LOW"

def log_anomaly(row, reasons, severity, recommendations):
    with open("./logs/anomaly_log.txt", "a", encoding="utf-8") as file:
        file.write("\n========== Anomaly Detected ==========\n")
        file.write(f"Time: {datetime.now()}\n")
        file.write(f"Requests Per Min: {row['requests_per_min']}\n")
        file.write(f"Avg Payload: {row['avg_payload_size']}\n")
        file.write(f"Unique IPs: {row['unique_ips']}\n")
        file.write(f"Severity: {severity}\n")
        file.write(f"Reason: {', '.join(reasons)}\n")
        file.write("Recommended Actions:\n")
        for r in recommendations:
            file.write(f" - {r}\n")


def generate_rule_recommendation(row):
    rules = []

    if row["requests_per_min"] > 100:
        rules.append("Apply rate limiting (e.g., max 50 requests/min per IP)")

    if row["avg_payload_size"] > 1200:
        rules.append("Enable deep payload inspection / block unusually large requests")

    if row["unique_ips"] > 10:
        rules.append("Possible botnet / distributed attack → enable IP reputation & bot protection")

    if not rules:
        rules.append("Monitor traffic pattern – potential emerging anomaly")

    return rules


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
                print("Reason: Statistically unusual behavior detected based on learned baseline")

            severity = calculate_severity(row)
            print(f"Severity Level: {severity}")
            recommendations = generate_rule_recommendation(row)
            log_anomaly(row, reasons if reasons else ["Statistical anomaly"], severity, recommendations)

            print("Recommended Security Actions:")
            for r in recommendations:
                print(" -", r)

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
    analyze_statistics(df)
    model = train_model(df)
    result = detect_anomalies(model, df)
    print(result)
    visualize_results(result)