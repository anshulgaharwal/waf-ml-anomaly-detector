from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
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
