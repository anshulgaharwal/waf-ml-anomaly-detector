from fastapi import FastAPI
import json

app = FastAPI()

@app.get("/")
def home():
    return {"message": "WAF ML Anomaly API is running"}

@app.get("/anomalies")
def get_anomalies():
    anomalies = []
    
    try:
        with open("./logs/anomaly_log.json", "r", encoding="utf-8") as file:
            for line in file:
                anomalies.append(json.loads(line))
    except:
        return {"status": "no anomaly logs found yet"}

    return {
        "count": len(anomalies),
        "data": anomalies
    }
