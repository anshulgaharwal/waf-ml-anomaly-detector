from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Body
import joblib
from .adaptive_learning import decide_new_policy
import pandas as pd
import os
import json

app = FastAPI()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/feedback")
def save_feedback(feedback: dict = Body(...)):
    """
    feedback = {
      "time": "...",
      "label": "FP" / "TP" / "Investigate"
    }
    """
    with open("./logs/feedback_log.json", "a", encoding="utf-8") as file:
        json.dump(feedback, file)
        file.write("\n")

    return {"status": "feedback recorded"}

@app.get("/anomalies")
def get_anomalies():
    anomalies = []

    try:
        with open("./logs/anomaly_log.json", "r", encoding="utf-8") as file:
            for line in file:
                try:
                    anomalies.append(json.loads(line))
                except:
                    # skip corrupted line
                    continue
    except FileNotFoundError:
        return {"status": "no anomaly logs found yet"}

    return {
        "count": len(anomalies),
        "data": anomalies
    }

@app.get("/model-metrics")
def get_model_metrics():
    metrics = {
        "total_anomalies": 0,
        "feedback_count": 0,
        "true_positive": 0,
        "false_positive": 0,
        "investigate": 0,
        "model_confidence": 0,
        "last_feedback_time": None
    }

    # Count anomalies logged
    try:
        with open("./logs/anomaly_log.json", "r", encoding="utf-8") as f:
            metrics["total_anomalies"] = sum(1 for _ in f)
    except:
        metrics["total_anomalies"] = 0

    # Count feedback
    try:
        with open("./logs/feedback_log.json", "r", encoding="utf-8") as f:
            for line in f:
                metrics["feedback_count"] += 1
                entry = json.loads(line)

                if entry["label"] == "TP":
                    metrics["true_positive"] += 1
                elif entry["label"] == "FP":
                    metrics["false_positive"] += 1
                elif entry["label"] == "Investigate":
                    metrics["investigate"] += 1

                metrics["last_feedback_time"] = entry["time"]
    except:
        pass

    # Model Confidence Score (simple smart logic)
    if metrics["feedback_count"] > 0:
        tp = metrics["true_positive"]
        fp = metrics["false_positive"]

        score = (tp / max(tp + fp, 1)) * 100
        metrics["model_confidence"] = round(score, 2)

    return metrics

@app.get("/adaptive-policy")
def adaptive_policy():
    policy = decide_new_policy()
    return policy

@app.post("/apply-policy")
def apply_policy():
    policy = decide_new_policy()

    # load policy state
    try:
        with open("./policy_state.json", "r") as f:
            state = json.load(f)
    except:
        state = {
            "current_contamination": 0.10,
            "last_update": None,
            "status": "unknown"
        }

    # If no meaningful policy yet
    if policy["status"] == "insufficient_feedback":
        return {
            "updated": False,
            "message": "Not enough feedback to adapt",
            "policy": policy
        }

    # Load training data
    df = pd.read_csv("./data/traffic_data.csv")

    contamination = policy["recommended_contamination"]

    # retrain model
    from sklearn.ensemble import IsolationForest
    model = IsolationForest(contamination=contamination, random_state=42)
    model.fit(df)

    # save new model
    joblib.dump(model, "./models/isolation_forest.pkl")

    # update policy state
    state["current_contamination"] = contamination
    state["last_update"] = str(datetime.now())
    state["status"] = policy["status"]

    with open("./policy_state.json", "w") as f:
        json.dump(state, f, indent=4)

    return {
        "updated": True,
        "message": "Model retrained & policy applied successfully",
        "new_policy": state
    }
