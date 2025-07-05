from flask import Flask, render_template, request
import joblib
from urllib.parse import urlparse
import re

app = Flask(__name__)
model = joblib.load('phishing_model.pkl')

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc

    features = []
    features.append(len(url))  # URL length
    features.append(url.count('.'))
    features.append(url.count('@'))
    features.append(url.count('-'))
    features.append(len(re.findall(r'\d', url)))  # digit count

    features.append(1 if parsed.scheme == 'https' else 0)
    features.append(1 if '-' in domain else 0)
    features.append(len(domain))

    suspicious_keywords = [
        'login', 'bank', 'account', 'update', 'free', 'secure',
        'webscr', 'confirm', 'verify', 'paypal', 'ebay', 'payment',
        'signin', 'click', 'bonus', 'offer', 'win', 'urgent', 'alert'
    ]
    features.append(sum(1 for kw in suspicious_keywords if kw in url.lower()))

    ip_pattern = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
    features.append(1 if ip_pattern.search(domain) else 0)

    shortening_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co']
    features.append(1 if any(service in url for service in shortening_services) else 0)

    features.append(len(domain.split('.')) - 2 if len(domain.split('.')) > 2 else 0)

    return features

def predict_url(url):
    features = extract_features(url)
    prediction = model.predict([features])[0]
    proba = model.predict_proba([features])[0][1]
    reasons = []

    if features[7] > 0:
        reasons.append("suspicious keyword")
    if features[8] == 1:
        reasons.append("IP address used")
    if features[9] == 1:
        reasons.append("shortened URL")
    if features[6] > 25:
        reasons.append("very long domain")

    result = "Phishing" if prediction == 1 else "Legitimate"
    return result, reasons, round(proba * 100, 2)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    confidence = None
    reasons = None
    if request.method == 'POST':
        url = request.form['url']
        result, reasons, confidence = predict_url(url)
    return render_template('index.html', result=result, reasons=', '.join(reasons) if reasons else None, confidence=confidence)

if __name__ == '__main__':
    app.run(debug=True)
