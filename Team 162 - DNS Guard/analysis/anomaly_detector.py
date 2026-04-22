import pickle
import os
import numpy as np
from sklearn.ensemble import IsolationForest
from analysis.feature_extractor import extract_features
from config.database import get_connection

MODEL_PATH = "models/isolation_forest.pkl"

def get_feature_vector(domain):
    f = extract_features(domain)
    return [
        f["domain_length"],
        f["entropy_score"],
        f["digit_ratio"],
        f["hyphen_count"],
        f["subdomain_count"]
    ]

def train_model():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT domain FROM dns_records")
    domains = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()

    if len(domains) < 10:
        print("Not enough data to train. Need at least 10 records.")
        return None

    X = [get_feature_vector(d) for d in domains]
    X = np.array(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )
    model.fit(X)

    os.makedirs("models", exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)

    print(f"Model trained on {len(domains)} domains and saved.")
    return model

def load_model():
    if not os.path.exists(MODEL_PATH):
        print("No model found. Training now...")
        return train_model()

    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)

def predict_anomaly(domain):
    model = load_model()
    if model is None:
        return None

    features = get_feature_vector(domain)
    X = np.array([features])

    prediction = model.predict(X)[0]
    score = model.score_samples(X)[0]

    is_anomaly = bool(prediction == -1)

    return {
        "domain": domain,
        "anomaly_score": round(float(score), 4),
        "is_anomaly": is_anomaly,
        "features": extract_features(domain),
        "reason": f"Anomaly score {score:.4f} — unusual pattern detected" if is_anomaly else "Normal pattern"
    }

def save_anomaly_result(result):
    conn = get_connection()
    cursor = conn.cursor()
    f = result["features"]

    query = """
        INSERT INTO anomaly_results
        (domain, anomaly_score, domain_length, entropy_score, digit_ratio, is_anomaly)
        VALUES (%s, %s, %s, %s, %s, %s)
    """

    cursor.execute(query, (
        result["domain"],
        result["anomaly_score"],
        f["domain_length"],
        f["entropy_score"],
        f["digit_ratio"],
        result["is_anomaly"]
    ))

    conn.commit()
    cursor.close()
    conn.close()

def analyze_all_records():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT domain FROM dns_records")
    domains = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()

    results = []
    for domain in domains:
        result = predict_anomaly(domain)
        if result:
            save_anomaly_result(result)
            results.append(result)

    return results