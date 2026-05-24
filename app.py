from flask import Flask, render_template, request, jsonify
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, roc_auc_score
import re
import base64
from io import BytesIO
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

app = Flask(__name__)

# Sample dataset
PHISHING_EMAILS = [
    "Verify your account immediately! Click here to confirm your identity: http://bit.ly/verify-amazon-account",
    "Urgent: Your bank account has been compromised. Update password now: http://secure-banking-update.xyz/login",
    "Congratulations! You've won $1000. Claim now: http://prize-claim.ru/verify",
    "PayPal Alert: Unusual activity detected. Re-authenticate: http://paypal-security.com/verify",
    "Your Apple ID will expire. Renew subscription: http://apple-id-renewal.xyz/update",
    "ALERT: Critical security issue. Reset your password immediately: http://office365-login-verify.tk",
    "Microsoft Account: Suspicious sign-in attempt. Verify identity: http://microsof-account-verify.xyz",
    "Your Facebook account is locked. Unlock now: http://facebook-unlock-account.xyz/verify",
    "Netflix: Your payment method declined. Update billing: http://netflix-update-payment.ru",
    "Confirm your Google account to restore access: http://google-verify-account.xyz",
    "Limited time offer! Claim your $500 gift card: http://amazon-gift-card.xyz/claim",
    "Your Instagram account needs verification. Verify here: http://instagram-verify-account.tk",
    "URGENT: Your Dropbox account will be deleted: http://dropbox-backup.xyz/save",
    "Verify your Uber account to continue: http://uber-verify.ru/auth",
    "Your LinkedIn is about to expire: http://linkedin-renew.xyz/extend"
]

LEGITIMATE_EMAILS = [
    "Welcome to our newsletter! Check out our latest blog posts and updates.",
    "Your order #12345 has been shipped. Track your package here.",
    "Thank you for subscribing! Please verify your email address to complete signup.",
    "Meeting reminder: Team standup tomorrow at 10 AM.",
    "Project update: Q2 deliverables completed successfully.",
    "Invoice #INV-2024-001 is ready for your review and payment.",
    "We've updated our privacy policy. Review the changes here.",
    "Your reservation at Hotel XYZ has been confirmed for June 15.",
    "Thank you for your purchase! Your receipt is attached.",
    "Weekly report: Sales increased by 15% this month.",
    "New course available: Introduction to Python programming.",
    "Customer feedback survey: We value your opinion.",
    "Event invitation: Join us for our annual conference.",
    "System maintenance: Scheduled downtime on Sunday.",
    "Your subscription has been renewed successfully."
]

class PhishingDetectorApp:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=100, stop_words='english', lowercase=True)
        self.nb_model = MultinomialNB()
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.results = None
        self.train_model()
    
    def create_dataset(self):
        emails = PHISHING_EMAILS + LEGITIMATE_EMAILS
        labels = [1] * len(PHISHING_EMAILS) + [0] * len(LEGITIMATE_EMAILS)
        return pd.DataFrame({'email': emails, 'label': labels})
    
    def train_model(self):
        df = self.create_dataset()
        X_text = self.vectorizer.fit_transform(df['email'])
        y = df['label'].values
        
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X_text, y, test_size=0.2, random_state=42, stratify=y
        )
        
        self.nb_model.fit(self.X_train, self.y_train)
        self.rf_model.fit(self.X_train, self.y_train)
        self.evaluate_models()
    
    def evaluate_models(self):
        nb_y_pred = self.nb_model.predict(self.X_test)
        rf_y_pred = self.rf_model.predict(self.X_test)
        
        self.results = {
            'nb_accuracy': accuracy_score(self.y_test, nb_y_pred),
            'rf_accuracy': accuracy_score(self.y_test, rf_y_pred),
            'nb_cm': confusion_matrix(self.y_test, nb_y_pred).tolist(),
            'rf_cm': confusion_matrix(self.y_test, rf_y_pred).tolist(),
            'nb_report': classification_report(self.y_test, nb_y_pred, 
                                              target_names=['Safe', 'Phishing'], output_dict=True),
            'rf_report': classification_report(self.y_test, rf_y_pred,
                                              target_names=['Safe', 'Phishing'], output_dict=True)
        }
    
    def predict(self, email):
        email_vector = self.vectorizer.transform([email])
        
        nb_pred = self.nb_model.predict(email_vector)[0]
        nb_proba = self.nb_model.predict_proba(email_vector)[0]
        
        rf_pred = self.rf_model.predict(email_vector)[0]
        rf_proba = self.rf_model.predict_proba(email_vector)[0]
        
        return {
            'nb_prediction': 'Phishing' if nb_pred == 1 else 'Safe',
            'nb_phishing_prob': float(nb_proba[1]),
            'nb_safe_prob': float(nb_proba[0]),
            'rf_prediction': 'Phishing' if rf_pred == 1 else 'Safe',
            'rf_phishing_prob': float(rf_proba[1]),
            'rf_safe_prob': float(rf_proba[0])
        }
    
    def get_confusion_matrix_chart(self):
        fig, axes = plt.subplots(1, 2, figsize=(12, 4))
        
        sns.heatmap(self.results['nb_cm'], annot=True, fmt='d', cmap='Blues', ax=axes[0],
                   xticklabels=['Safe', 'Phishing'], yticklabels=['Safe', 'Phishing'])
        axes[0].set_title(f'Naive Bayes\nAccuracy: {self.results["nb_accuracy"]:.2%}')
        axes[0].set_ylabel('True Label')
        axes[0].set_xlabel('Predicted Label')
        
        sns.heatmap(self.results['rf_cm'], annot=True, fmt='d', cmap='Greens', ax=axes[1],
                   xticklabels=['Safe', 'Phishing'], yticklabels=['Safe', 'Phishing'])
        axes[1].set_title(f'Random Forest\nAccuracy: {self.results["rf_accuracy"]:.2%}')
        axes[1].set_ylabel('True Label')
        axes[1].set_xlabel('Predicted Label')
        
        plt.tight_layout()
        
        img = BytesIO()
        plt.savefig(img, format='png', bbox_inches='tight')
        img.seek(0)
        img_base64 = base64.b64encode(img.getvalue()).decode()
        plt.close()
        
        return img_base64

detector = PhishingDetectorApp()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stats')
def stats():
    return jsonify({
        'nb_accuracy': f"{detector.results['nb_accuracy']:.2%}",
        'rf_accuracy': f"{detector.results['rf_accuracy']:.2%}",
        'test_samples': len(detector.y_test),
        'training_samples': len(detector.y_train)
    })

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    email = data.get('email', '')
    
    if not email:
        return jsonify({'error': 'Email text is required'}), 400
    
    result = detector.predict(email)
    return jsonify(result)

@app.route('/confusion-matrix')
def confusion_matrix_chart():
    chart = detector.get_confusion_matrix_chart()
    return jsonify({'chart': f'data:image/png;base64,{chart}'})

@app.route('/metrics')
def metrics():
    return jsonify({
        'nb_report': detector.results['nb_report'],
        'rf_report': detector.results['rf_report']
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
