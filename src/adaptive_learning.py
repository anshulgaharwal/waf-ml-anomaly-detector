import json
import os

def analyze_feedback():
    metrics = {
        "tp": 0,
        "fp": 0,
        "investigate": 0,
        "total_feedback": 0
    }

    try:
        with open("./logs/feedback_log.json", "r", encoding="utf-8") as f:
            for line in f:
                entry = json.loads(line)
                metrics["total_feedback"] += 1

                if entry["label"] == "TP":
                    metrics["tp"] += 1
                elif entry["label"] == "FP":
                    metrics["fp"] += 1
                elif entry["label"] == "Investigate":
                    metrics["investigate"] += 1
    except:
        return metrics

    return metrics


def decide_new_policy():
    feedback = analyze_feedback()

    if feedback["total_feedback"] < 5:
        return {
            "status": "insufficient_feedback",
            "message": "Not enough feedback to adapt yet",
            "recommended_contamination": 0.10
        }

    tp = feedback["tp"]
    fp = feedback["fp"]

    if fp > tp:
        return {
            "status": "too_strict",
            "message": "Too many false positives. Relaxing model sensitivity",
            "recommended_contamination": 0.15
        }

    if tp > fp and tp >= 3:
        return {
            "status": "accurate",
            "message": "Model performing well. Keeping stable",
            "recommended_contamination": 0.08
        }

    return {
        "status": "neutral",
        "message": "No strong signal. Keep current setting",
        "recommended_contamination": 0.10
    }
