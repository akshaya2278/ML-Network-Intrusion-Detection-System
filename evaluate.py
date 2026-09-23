from data_loader import load_and_prep_data
from agent import NetworkIntrusionAgent
from sklearn.metrics import classification_report, confusion_matrix
import pandas as pd

if __name__ == "__main__":
    df_train, df_test = load_and_prep_data()
    
    agent = NetworkIntrusionAgent()
    agent.train(df_train)
    
    print("\nEvaluating on Test Data...")
    results = agent.predict(df_test)
    
    # Binary Evaluation
    print("\n--- Binary Classification (Normal vs Suspicious) ---")
    y_true_binary = df_test['is_suspicious']
    y_pred_binary = (results['risk_score'] >= 0.5).astype(int)
    print(classification_report(y_true_binary, y_pred_binary, target_names=['Normal', 'Suspicious']))
    
    # Multi-class Evaluation
    print("\n--- Attack Category Classification ---")
    y_true_multi = df_test['attack_category']
    y_pred_multi = results['predicted_attack']
    
    # Align classes for the report
    labels = sorted(list(set(y_true_multi) | set(y_pred_multi)))
    print(classification_report(y_true_multi, y_pred_multi, labels=labels, zero_division=0))
    
    print("\n--- Confusion Matrix ---")
    cm = confusion_matrix(y_true_multi, y_pred_multi, labels=labels)
    cm_df = pd.DataFrame(cm, index=labels, columns=labels)
    print(cm_df)
    
    # Save a sample for the dashboard
    results.sample(1000).to_csv("sample_dashboard_data.csv", index=False)
    print("\nSaved 'sample_dashboard_data.csv' for the Streamlit App.")