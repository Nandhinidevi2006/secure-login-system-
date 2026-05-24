# Phishing Email Detection Model

## Overview
This machine learning model detects phishing emails using Scikit-learn. It classifies emails as either "Phishing" or "Safe" based on textual content, keywords, and URL patterns.

## Features
- **TF-IDF Vectorization**: Extracts text features from emails
- **Two Classification Models**: 
  - Naive Bayes (fast, baseline)
  - Random Forest (better accuracy)
- **Comprehensive Evaluation**:
  - Accuracy score
  - Confusion matrix
  - ROC AUC score
  - Classification report with precision, recall, and F1-score
- **Visualizations**: ROC curves and confusion matrices
- **Real-time Prediction**: Classify custom emails

## Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

## Dataset

The model is trained on:
- **15 Phishing Emails**: Containing common phishing indicators (urgency, verification requests, suspicious URLs)
- **15 Legitimate Emails**: Standard business communications

### Phishing Indicators Detected:
- Suspicious keywords: verify, confirm, urgent, password, update, claim, alert, renew, reset, unlock, expired
- Suspicious domains: .xyz, .tk, .ru, .ml, bit.ly, tinyurl
- URL presence and patterns

## Usage

### Run the Complete Analysis

```bash
python phishing_detector.py
```

This will:
1. Create the dataset
2. Extract and vectorize features
3. Train both Naive Bayes and Random Forest models
4. Evaluate model performance
5. Display confusion matrices and classification reports
6. Generate visualizations
7. Test on sample emails

### Output Files
- `phishing_detection_results.png`: Confusion matrices, ROC curves, and performance comparison

## Expected Results

### Naive Bayes Classifier
- **Accuracy**: ~93%
- **Precision**: High confidence in phishing predictions
- **Recall**: Good detection of actual phishing emails

### Random Forest Classifier
- **Accuracy**: ~93-100%
- **Better generalization** on unseen data
- **Handles non-linear relationships** better

## Model Performance Metrics

### Confusion Matrix Interpretation
```
                Predicted
              Safe  Phishing
Actual  Safe   TN     FP
        Phishing FN    TP
```

- **True Negative (TN)**: Correctly identified safe emails
- **False Positive (FP)**: Safe emails incorrectly flagged as phishing
- **False Negative (FN)**: Phishing emails missed (most critical)
- **True Positive (TP)**: Correctly identified phishing emails

### Key Metrics
- **Accuracy**: (TP + TN) / Total
- **Precision**: TP / (TP + FP) - reliability of positive predictions
- **Recall**: TP / (TP + FN) - ability to find all phishing emails
- **F1-Score**: Harmonic mean of precision and recall
- **ROC AUC**: Area under the ROC curve (0.5 = random, 1.0 = perfect)

## Feature Engineering

### TF-IDF Features
- Term Frequency-Inverse Document Frequency
- Captures importance of words across all emails
- Reduces weight of common words

### Additional Features Considered
- Suspicious keyword count
- URL count in email
- Suspicious domain detection

## How to Extend

### Add More Training Data
Modify `PHISHING_EMAILS` and `LEGITIMATE_EMAILS` lists in the script:

```python
PHISHING_EMAILS = [
    "Your email here",
    # More emails...
]
```

### Use Custom Dataset
Replace the lists with CSV file:

```python
df = pd.read_csv('emails.csv')  # Must have 'email' and 'label' columns
```

### Adjust Model Parameters
- Increase `max_features` in TfidfVectorizer for more features
- Tune `n_estimators` in RandomForestClassifier
- Modify suspicious keywords list

### Try Other Algorithms
```python
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression

model = SVC(kernel='rbf', probability=True)  # or LogisticRegression()
```

## Classification Example

```python
detector = PhishingDetector()
# ... training code ...

result = detector.predict("Click here to verify your account: http://secure-bank.xyz")
print(result['prediction'])  # Output: 'Phishing'
print(result['phishing_probability'])  # Output: 0.95
```

## Performance Considerations

- **Training Time**: < 1 second
- **Prediction Time**: < 1ms per email
- **Memory**: ~2-5 MB for trained models
- **Scalability**: Can handle millions of emails with optimization

## Limitations

- Limited training data (30 emails) - production models need thousands
- Simple feature extraction - advanced methods like LSTM could improve results
- Language-specific (English) - needs adaptation for other languages
- May miss novel phishing techniques not in training data

## Future Improvements

1. **Deep Learning**: Use neural networks for better feature learning
2. **Domain Authentication**: Check SPF, DKIM, DMARC records
3. **Attachment Analysis**: Scan for malicious attachments
4. **User Behavior**: Track user's typical email patterns
5. **Real-time Updates**: Update model with new phishing patterns
6. **Multi-language Support**: Handle emails in multiple languages

## Author Notes

This model demonstrates core concepts of:
- Text classification using TF-IDF
- Model training and evaluation
- Confusion matrices and performance metrics
- ROC curves and AUC scores
- Visualization of ML results

For production use, combine with other security measures (authentication, URL checking, sandboxing).
