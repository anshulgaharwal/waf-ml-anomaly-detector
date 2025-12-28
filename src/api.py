from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Body
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
