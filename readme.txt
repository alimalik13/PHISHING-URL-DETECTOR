PHISHING URL DETECTOR - 

Developed by: 
  - Ali Nawaz and Waqar Hassan 

---

PROJECT DESCRIPTION:
A web-based application to detect whether a given URL is Phishing or Legitimate.
Built using a trained RandomForestClassifier model and Flask for the front end.

---

FEATURES:
- Extracts key features from URLs (length, IP usage, suspicious keywords, etc.)
- Predicts using a trained model (phishing_model.pkl)
- Displays prediction result, probability, and explanation
- Interactive Bootstrap-based web UI

---

HOW TO RUN:

1. Install requirements:
   pip install -r requirements.txt

2. Run the app:
   python main.py

3. Open your browser and go to:
   http://127.0.0.1:5000

---

FILES STRUCTURE:

- main.py .................... Flask backend & prediction logic
- phishing_model.pkl ........ Pre-trained ML model
- templates/index.html ...... Front-end HTML (Bootstrap)
- feature_extraction.py ..... URL feature logic (integrated into main.py)
- phishing.csv / dataset.csv. Example datasets used for training
- scaler.pkl ................ (Optional) If using scaling during training
- requirements.txt .......... All required Python libraries
- readme.txt ................ This file

---

NOTES:
- Model trained using scikit-learn 1.7.0
- If version mismatch occurs, retrain or match sklearn version

---

CONTACT:
ali.malik9545@gmail.com
