import os, joblib, numpy as np, pandas as pd
import matplotlib.pyplot as plt, seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

# Only use features we can extract from URL structure (no network calls)
URL_FEATURES = [
    "qty_dot_url","qty_hyphen_url","qty_underline_url","qty_slash_url",
    "qty_questionmark_url","qty_equal_url","qty_at_url","qty_and_url",
    "qty_exclamation_url","qty_space_url","qty_tilde_url","qty_comma_url",
    "qty_plus_url","qty_asterisk_url","qty_hashtag_url","qty_dollar_url",
    "qty_percent_url","qty_tld_url","length_url",
    "qty_dot_domain","qty_hyphen_domain","qty_underline_domain",
    "qty_vowels_domain","domain_length","domain_in_ip","server_client_domain",
    "qty_dot_directory","qty_hyphen_directory","qty_underline_directory",
    "qty_slash_directory","directory_length",
    "qty_dot_params","qty_equal_params","qty_and_params",
    "params_length","qty_params","email_in_url","url_shortened",
    "tls_ssl_certificate","qty_redirects"
]

def train():
    print("[PhishGuard] Loading dataset...")
    df = pd.read_csv("data/phishing_dataset.csv")
    print(f"[PhishGuard] Rows: {len(df):,}")

    # Use only URL structure features
    available = [f for f in URL_FEATURES if f in df.columns]
    print(f"[PhishGuard] Using {len(available)} URL-structure features")

    X = df[available].fillna(0)
    y = df["phishing"].astype(int)

    feature_names = list(X.columns)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"[PhishGuard] Train: {len(X_train):,} | Test: {len(X_test):,}")

    print("[PhishGuard] Training XGBoost...")
    model = XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8,
        eval_metric="logloss", random_state=42, n_jobs=-1
    )
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
    joblib.dump(model,        "models/phishguard_model.pkl")
    joblib.dump(scaler,       "models/phishguard_scaler.pkl")
    joblib.dump(feature_names,"models/feature_names.pkl")
    print("[PhishGuard] Model saved!")

    # Plot
    fig, axes = plt.subplots(1,2,figsize=(12,5))
    sns.heatmap(confusion_matrix(y_test,y_pred), annot=True, fmt="d", cmap="Reds",
                xticklabels=["Legit","Phish"], yticklabels=["Legit","Phish"], ax=axes[0])
    axes[0].set_title("Confusion Matrix")
    imp = pd.DataFrame({"f":feature_names,"i":model.feature_importances_}).sort_values("i",ascending=True).tail(15)
    axes[1].barh(imp["f"], imp["i"], color="#e74c3c")
    axes[1].set_title("Top Features")
    plt.tight_layout()
    plt.savefig("models/evaluation_plots.png", dpi=150)
    plt.close()
    print("[PhishGuard] Done!")

if __name__ == "__main__":
    train()
