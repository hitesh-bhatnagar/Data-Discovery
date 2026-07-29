"""
ML-based PII classification using TF-IDF + RandomForest.
Trained on PII-related terms in English + Indian context.
"""
from __future__ import annotations

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier

_TRAINING_DATA = [
    ("aadhaar number 1234 5678 9012", "AADHAAR"),
    ("uid 123456789012", "AADHAAR"),
    ("pan ABCDE1234F", "PAN_CARD"),
    ("pan number", "PAN_CARD"),
    ("passport A1234567", "PASSPORT_IN"),
    ("voter id ABC1234567", "VOTER_ID"),
    ("driving license DL-0420110012345", "DRIVING_LICENSE"),
    ("gstin 27AAECS1234F1Z5", "GSTIN"),
    ("ifsc SBIN0001234", "IFSC_CODE"),
    ("phone +919876543210", "PHONE_IN"),
    ("mobile 9876543210", "PHONE_IN"),
    ("email user@example.com", "EMAIL"),
    ("credit card 4111111111111111", "CREDIT_CARD"),
    ("debit card", "CREDIT_CARD"),
    ("upi user@paytm", "UPI_ID"),
    ("ip address 192.168.1.1", "IP_ADDRESS"),
    ("pin code 110001", "PIN_CODE"),
    ("salary amount 50000", "FINANCIAL"),
    ("bank account 1234567890", "BANK_ACCOUNT"),
    ("date of birth 01-01-1990", "DATE_OF_BIRTH"),
    ("employee name john", "PERSON_NAME"),
    ("address 123 main street", "ADDRESS"),
    ("medical history", "HEALTH_DATA"),
    ("biometric fingerprint", "BIOMETRIC"),
    ("password secret123", "PASSWORD"),
    ("hello world this is a test", "CLEAN"),
    ("meeting at 3pm tomorrow", "CLEAN"),
    ("project report summary", "CLEAN"),
    ("quarterly results review", "CLEAN"),
]

_vectorizer = TfidfVectorizer(ngram_range=(1, 3), max_features=5000)
_clf = RandomForestClassifier(n_estimators=100, random_state=42)

_X_text = [t for t, _ in _TRAINING_DATA]
_y = [l for _, l in _TRAINING_DATA]
_X_vec = _vectorizer.fit_transform(_X_text)
_clf.fit(_X_vec, _y)

_TRAINED = True


def classify(text: str) -> tuple[str, float]:
    if not text or not text.strip():
        return ("CLEAN", 0.0)
    vec = _vectorizer.transform([text[:1000]])
    probs = _clf.predict_proba(vec)[0]
    pred = _clf.predict(vec)[0]
    confidence = float(max(probs)) * 100
    return (pred, confidence)
