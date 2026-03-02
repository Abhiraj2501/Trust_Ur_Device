import pickle
import os

# Load trained model and vectorizer
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model/phishing_model.pkl")
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "model/vectorizer.pkl")

model = pickle.load(open(MODEL_PATH, "rb"))
vectorizer = pickle.load(open(VECTORIZER_PATH, "rb"))

def analyze_email(subject, body, sender):
    # Combine all email parts into one string
    full_text = f"{sender} {subject} {body}"
    
    # Transform using trained vectorizer
    vec = vectorizer.transform([full_text])
    
    # Predict
    prediction = model.predict(vec)[0]
    probability = model.predict_proba(vec)[0]
    confidence = max(probability) * 100
    score = int(prediction)
    
    # Map to risk level
    if prediction == 1 and confidence > 80:
        risk = "HIGH"
    elif prediction == 1 and confidence > 60:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    
    # Build flags for explainability
    flags = []
    if prediction == 1:
        # Find which words triggered the model
        feature_names = vectorizer.get_feature_names_out()
        vec_array = vec.toarray()[0]
        top_indices = vec_array.argsort()[-5:][::-1]
        top_words = [feature_names[i] for i in top_indices if vec_array[i] > 0]
        
        for word in top_words:
            flags.append(("ml_detection", word))
    
    return risk, flags, score