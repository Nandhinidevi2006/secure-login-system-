import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report, roc_auc_score, roc_curve
import matplotlib.pyplot as plt
import seaborn as sns
import re
from urllib.parse import urlparse

# Sample dataset of phishing and legitimate emails
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

class PhishingDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=100, stop_words='english', lowercase=True)
        self.model = MultinomialNB()
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        self.feature_names = None
        
    def create_dataset(self):
        """Create labeled dataset from phishing and legitimate emails"""
        emails = PHISHING_EMAILS + LEGITIMATE_EMAILS
        labels = [1] * len(PHISHING_EMAILS) + [0] * len(LEGITIMATE_EMAILS)  # 1: Phishing, 0: Safe
        
        df = pd.DataFrame({'email': emails, 'label': labels})
        return df
    
    def extract_additional_features(self, email):
        """Extract URL and keyword-based features"""
        features = {}
        
        # Count suspicious keywords
        suspicious_keywords = ['verify', 'confirm', 'urgent', 'account', 'password', 'update', 
                             'click', 'claim', 'alert', 'renew', 'reset', 'unlock', 'expired']
        email_lower = email.lower()
        features['suspicious_keyword_count'] = sum(email_lower.count(kw) for kw in suspicious_keywords)
        
        # Count URLs
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, email)
        features['url_count'] = len(urls)
        
        # Check for suspicious domain characteristics
        features['has_suspicious_domain'] = any(
            domain in email.lower() for domain in ['.xyz', '.tk', '.ru', '.ml', 'bit.ly', 'tinyurl']
        )
        
        return features
    
    def prepare_data(self, df):
        """Prepare training and test data"""
        X_text = self.vectorizer.fit_transform(df['email'])
        self.feature_names = self.vectorizer.get_feature_names_out()
        
        y = df['label'].values
        
        # Split data
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X_text, y, test_size=0.2, random_state=42, stratify=y
        )
        
    def train_model(self):
        """Train the Naive Bayes model"""
        self.model.fit(self.X_train, self.y_train)
        
    def train_random_forest(self):
        """Train Random Forest model for comparison"""
        self.rf_model.fit(self.X_train, self.y_train)
    
    def evaluate_model(self):
        """Evaluate model performance"""
        # Naive Bayes predictions
        y_pred = self.model.predict(self.X_test)
        y_pred_proba = self.model.predict_proba(self.X_test)[:, 1]
        
        # Random Forest predictions
        rf_y_pred = self.rf_model.predict(self.X_test)
        rf_y_pred_proba = self.rf_model.predict_proba(self.X_test)[:, 1]
        
        # Accuracy
        nb_accuracy = accuracy_score(self.y_test, y_pred)
        rf_accuracy = accuracy_score(self.y_test, rf_y_pred)
        
        # Confusion Matrix
        nb_cm = confusion_matrix(self.y_test, y_pred)
        rf_cm = confusion_matrix(self.y_test, rf_y_pred)
        
        # ROC AUC
        nb_auc = roc_auc_score(self.y_test, y_pred_proba)
        rf_auc = roc_auc_score(self.y_test, rf_y_pred_proba)
        
        return {
            'nb_accuracy': nb_accuracy,
            'rf_accuracy': rf_accuracy,
            'nb_cm': nb_cm,
            'rf_cm': rf_cm,
            'nb_auc': nb_auc,
            'rf_auc': rf_auc,
            'nb_y_pred': y_pred,
            'rf_y_pred': rf_y_pred,
            'nb_y_pred_proba': y_pred_proba,
            'rf_y_pred_proba': rf_y_pred_proba,
            'classification_report_nb': classification_report(self.y_test, y_pred, 
                                                             target_names=['Safe', 'Phishing']),
            'classification_report_rf': classification_report(self.y_test, rf_y_pred,
                                                             target_names=['Safe', 'Phishing'])
        }
    
    def predict(self, email):
        """Predict if a single email is phishing or safe"""
        email_vector = self.vectorizer.transform([email])
        prediction = self.model.predict(email_vector)[0]
        probability = self.model.predict_proba(email_vector)[0]
        
        return {
            'email': email,
            'prediction': 'Phishing' if prediction == 1 else 'Safe',
            'phishing_probability': probability[1],
            'safe_probability': probability[0]
        }
    
    def plot_results(self, results):
        """Create visualizations of model performance"""
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        # Confusion Matrix - Naive Bayes
        sns.heatmap(results['nb_cm'], annot=True, fmt='d', cmap='Blues', ax=axes[0, 0],
                   xticklabels=['Safe', 'Phishing'], yticklabels=['Safe', 'Phishing'])
        axes[0, 0].set_title(f'Naive Bayes Confusion Matrix\nAccuracy: {results["nb_accuracy"]:.2%}')
        axes[0, 0].set_ylabel('True Label')
        axes[0, 0].set_xlabel('Predicted Label')
        
        # Confusion Matrix - Random Forest
        sns.heatmap(results['rf_cm'], annot=True, fmt='d', cmap='Greens', ax=axes[0, 1],
                   xticklabels=['Safe', 'Phishing'], yticklabels=['Safe', 'Phishing'])
        axes[0, 1].set_title(f'Random Forest Confusion Matrix\nAccuracy: {results["rf_accuracy"]:.2%}')
        axes[0, 1].set_ylabel('True Label')
        axes[0, 1].set_xlabel('Predicted Label')
        
        # ROC Curves
        fpr_nb, tpr_nb, _ = roc_curve(self.y_test, results['nb_y_pred_proba'])
        fpr_rf, tpr_rf, _ = roc_curve(self.y_test, results['rf_y_pred_proba'])
        
        axes[1, 0].plot(fpr_nb, tpr_nb, label=f'Naive Bayes (AUC: {results["nb_auc"]:.3f})')
        axes[1, 0].plot(fpr_rf, tpr_rf, label=f'Random Forest (AUC: {results["rf_auc"]:.3f})')
        axes[1, 0].plot([0, 1], [0, 1], 'k--', label='Random')
        axes[1, 0].set_xlabel('False Positive Rate')
        axes[1, 0].set_ylabel('True Positive Rate')
        axes[1, 0].set_title('ROC Curves')
        axes[1, 0].legend()
        axes[1, 0].grid(True, alpha=0.3)
        
        # Model Comparison
        models = ['Naive Bayes', 'Random Forest']
        accuracies = [results['nb_accuracy'], results['rf_accuracy']]
        aucs = [results['nb_auc'], results['rf_auc']]
        
        x = np.arange(len(models))
        width = 0.35
        axes[1, 1].bar(x - width/2, accuracies, width, label='Accuracy', color='skyblue')
        axes[1, 1].bar(x + width/2, aucs, width, label='ROC AUC', color='lightcoral')
        axes[1, 1].set_ylabel('Score')
        axes[1, 1].set_title('Model Performance Comparison')
        axes[1, 1].set_xticks(x)
        axes[1, 1].set_xticklabels(models)
        axes[1, 1].set_ylim([0, 1.1])
        axes[1, 1].legend()
        axes[1, 1].grid(True, alpha=0.3, axis='y')
        
        plt.tight_layout()
        plt.savefig('c:\\Users\\nandh\\Downloads\\task 4\\phishing_detection_results.png', dpi=300, bbox_inches='tight')
        print("✓ Visualization saved: phishing_detection_results.png")
        plt.close()


def main():
    print("=" * 60)
    print("PHISHING EMAIL DETECTION MODEL")
    print("=" * 60)
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Create dataset
    print("\n1. Creating dataset...")
    df = detector.create_dataset()
    print(f"   Total emails: {len(df)}")
    print(f"   Phishing emails: {(df['label'] == 1).sum()}")
    print(f"   Legitimate emails: {(df['label'] == 0).sum()}")
    
    # Prepare data
    print("\n2. Preparing data...")
    detector.prepare_data(df)
    print(f"   Training samples: {len(detector.X_train.toarray())}")
    print(f"   Test samples: {len(detector.X_test.toarray())}")
    print(f"   Features extracted: {len(detector.feature_names)}")
    
    # Train models
    print("\n3. Training models...")
    detector.train_model()
    print("   ✓ Naive Bayes model trained")
    detector.train_random_forest()
    print("   ✓ Random Forest model trained")
    
    # Evaluate models
    print("\n4. Evaluating models...")
    results = detector.evaluate_model()
    
    print("\n" + "=" * 60)
    print("NAIVE BAYES CLASSIFIER RESULTS")
    print("=" * 60)
    print(f"Accuracy: {results['nb_accuracy']:.2%}")
    print(f"ROC AUC Score: {results['nb_auc']:.3f}")
    print("\nConfusion Matrix:")
    print(results['nb_cm'])
    print("\nClassification Report:")
    print(results['classification_report_nb'])
    
    print("\n" + "=" * 60)
    print("RANDOM FOREST CLASSIFIER RESULTS")
    print("=" * 60)
    print(f"Accuracy: {results['rf_accuracy']:.2%}")
    print(f"ROC AUC Score: {results['rf_auc']:.3f}")
    print("\nConfusion Matrix:")
    print(results['rf_cm'])
    print("\nClassification Report:")
    print(results['classification_report_rf'])
    
    # Test on sample emails
    print("\n" + "=" * 60)
    print("SAMPLE PREDICTIONS")
    print("=" * 60)
    
    test_emails = [
        "Click here to verify your account: http://secure-bank-verify.xyz",
        "Your order #12345 has been shipped successfully.",
        "URGENT: Update your password now: http://paypal-login.ru",
        "Meeting scheduled for tomorrow at 2 PM in conference room B."
    ]
    
    for email in test_emails:
        result = detector.predict(email)
        print(f"\nEmail: {email[:60]}...")
        print(f"Prediction: {result['prediction']}")
        print(f"Phishing Probability: {result['phishing_probability']:.2%}")
        print(f"Safe Probability: {result['safe_probability']:.2%}")
    
    # Create visualizations
    print("\n5. Creating visualizations...")
    detector.plot_results(results)
    
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE!")
    print("=" * 60)


if __name__ == "__main__":
    main()
