import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from xgboost import XGBClassifier
from preprocessor import get_preprocessor

class NetworkIntrusionAgent:
    def __init__(self):
        self.preprocessor = None
        self.binary_clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        self.multiclass_clf = XGBClassifier(eval_metric='mlogloss', random_state=42)
        self.anomaly_detector = IsolationForest(contamination=0.05, random_state=42)
        self.attack_classes = None

    def train(self, df_train):
        print("Preprocessing data...")
        self.preprocessor, _, _ = get_preprocessor(df_train)
        X = df_train.drop(columns=['label', 'attack_category', 'is_suspicious'])
        X_processed = self.preprocessor.fit_transform(X)
        
        y_binary = df_train['is_suspicious']
        y_multi = df_train['attack_category']
        
        # 1. Train Binary Classifier
        print("Training Binary Classifier...")
        self.binary_clf.fit(X_processed, y_binary)
        
        # 2. Train Multi-class Classifier (on suspicious traffic only)
        print("Training Multi-class Classifier...")
        suspicious_mask = (y_binary == 1)
        # Factorize labels for XGBoost
        self.attack_classes, y_multi_encoded = np.unique(y_multi[suspicious_mask], return_inverse=True)
        self.multiclass_clf.fit(X_processed[suspicious_mask], y_multi_encoded)
        
        # 3. Train Anomaly Detector (on normal traffic only)
        print("Training Anomaly Detector...")
        normal_mask = (y_binary == 0)
        self.anomaly_detector.fit(X_processed[normal_mask])
        print("Training Complete!")

    def predict(self, df):
        X = df.drop(columns=['label', 'attack_category', 'is_suspicious'], errors='ignore')
        X_processed = self.preprocessor.transform(X)
        
        # Binary probabilities
        binary_probs = self.binary_clf.predict_proba(X_processed)[:, 1]
        
        # Anomaly scoring: ISF returns -1 for anomaly, 1 for normal. 
        # Convert to 0-1 scale where 1 is highly anomalous.
        anomaly_scores = self.anomaly_detector.decision_function(X_processed)
        anomaly_probs = 1 - (anomaly_scores - anomaly_scores.min()) / (anomaly_scores.max() - anomaly_scores.min())
        
        # Multi-class predictions
        multi_preds_encoded = self.multiclass_clf.predict(X_processed)
        multi_preds = self.attack_classes[multi_preds_encoded]
        
        results = df.copy()
        results['suspicious_prob'] = binary_probs
        results['anomaly_score'] = anomaly_probs
        
        # Risk Scoring: Weighted combination of explicit known-attack probability and novel anomaly score
        results['risk_score'] = (0.7 * binary_probs) + (0.3 * anomaly_probs)
        
        results['risk_level'] = pd.cut(
            results['risk_score'], 
            bins=[-np.inf, 0.4, 0.75, np.inf], 
            labels=['Low', 'Medium', 'High']
        )
        
        results['predicted_attack'] = np.where(
            (results['risk_level'] == 'Low') & (results['anomaly_score'] < 0.8), 
            'normal', 
            multi_preds
        )
        
        # Mark as Novel if anomaly is extremely high but binary prob is low
        novel_mask = (results['anomaly_score'] > 0.85) & (results['suspicious_prob'] < 0.4)
        results.loc[novel_mask, 'predicted_attack'] = 'unknown/novel'
        
        # Generate Alerts
        results['alert'] = results.apply(self._generate_alert, axis=1)
        
        return results

    def _generate_alert(self, row):
        if row['risk_level'] in ['High', 'Medium']:
            reason = f"Identified as {row['predicted_attack']}."
            if row['predicted_attack'] == 'unknown/novel':
                reason = "Highly unusual traffic pattern detected (Potential Zero-Day)."
                
            return (f"🚨 ALERT [{row['risk_level']} RISK]: {reason} "
                    f"(Risk Score: {row['risk_score']:.2f}, Protocol: {row['protocol_type']}, "
                    f"Src Bytes: {row['src_bytes']})")
        return None