import os, joblib, numpy as np, pandas as pd
import matplotlib.pyplot as plt, seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

def train_phishguard_model():
    print("\n[PhishGuard] Loading dataset...")
    df = pd.read_csv("data/phishing_dataset.csv")
    print(f"[PhishGuard] Rows: {len(df):,} | Columns: {len(df.columns)}")
    print(f"[PhishGuard] Label distribution:\n{df['phishing'].value_counts()}\n")
    X = df.drop(columns=["phishing"])
    y = df["phishing"].astype(int)
    X = X.select_dtypes(include=[np.number]).fillna(0)
    feature_names = list(X.columns)
    print(f"[PhishGuard] Features: {len(feature_names)}")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42, stratify=y)
    print(f"[PhishGuard] Train: {len(X_train):,} | Test: {len(X_test):,}")
    print("\n[PhishGuard] Training XGBoost... (1-2 minutes)")
    model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8, eval_metric="logloss", random_state=42, n_jobs=-1)
    model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=50)
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:,1]
    print("\n" + "="*50)
    print(f"  Accuracy  : {accuracy_score(y_test,y_pred)*100:.2f}%")
    print(f"  Precision : {precision_score(y_test,y_pred)*100:.2f}%")
    print(f"  Recall    : {recall_score(y_test,y_pred)*100:.2f}%")
    print(f"  F1 Score  : {f1_score(y_test,y_pred)*100:.2f}%")
    print(f"  AUC-ROC   : {roc_auc_score(y_test,y_prob)*100:.2f}%")
    print("="*50)
    print(classification_report(y_test, y_pred, target_names=["Legitimate","Phishing"]))
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, "models/phishguard_model.pkl")
    joblib.dump(scaler, "models/phishguard_scaler.pkl")
    joblib.dump(feature_names, "models/feature_names.pkl")
    print("[PhishGuard] Model saved!")
    fig, axes = plt.subplots(1,2,figsize=(12,5))
    sns.heatmap(confusion_matrix(y_test,y_pred), annot=True, fmt="d", cmap="Reds", xticklabels=["Legit","Phish"], yticklabels=["Legit","Phish"], ax=axes[0])
    axes[0].set_title("Confusion Matrix")
    imp = pd.DataFrame({"f":feature_names,"i":model.feature_importances_}).sort_values("i",ascending=True).tail(15)
    axes[1].barh(imp["f"], imp["i"], color="#e74c3c")
    axes[1].set_title("Top 15 Features")
    plt.tight_layout()
    plt.savefig("models/evaluation_plots.png", dpi=150)
    plt.close()
    print("[PhishGuard] Plots saved!")

if __name__ == "__main__":
    train_phishguard_model()
