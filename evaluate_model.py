import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pickle
import os
import seaborn as sns
import matplotlib.pyplot as plt

# --- Define File Paths ---
DATA_PATH = os.path.join("data", "heart1.csv")
MODEL_DIR = "model"
MODEL_PATH = os.path.join(MODEL_DIR, "heart_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")

# --- Load Dataset ---
print("--- Loading Dataset ---")
try:
    # Column names are based on the UCI dataset documentation.
    # The provided CSV does not have a header.
    col_names = ['age', 'sex', 'cp', 'trestbps', 'chol', 'fbs', 'restecg', 'thalach',
                 'exang', 'oldpeak', 'slope', 'ca', 'thal', 'target']
    df = pd.read_csv(DATA_PATH, header=None, names=col_names)
except FileNotFoundError:
    print(f"Error: The file {DATA_PATH} was not found.")
    exit()
print("Dataset loaded successfully.\n")

# --- Data Cleaning and Preprocessing ---
print("--- Preprocessing Data ---")
df.replace('?', pd.NA, inplace=True)
df.dropna(inplace=True)
for col in df.columns:
    df[col] = pd.to_numeric(df[col], errors='coerce')
df.dropna(inplace=True)
df['target'] = df['target'].apply(lambda x: 1 if x > 0 else 0)
X = df.drop('target', axis=1)
y = df['target']
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("Data preprocessing complete.\n")

# --- Model Training ---
print("--- Training the Random Forest Model ---")
model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=5)
model.fit(X_train_scaled, y_train)
print("Model training complete.\n")

# --- Model Evaluation ---
print("--- Evaluating Model Performance ---")
y_pred = model.predict(X_test_scaled)

# Accuracy
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}\n")

# Classification Report (Precision, Recall, F1-Score)
print("Classification Report:")
# Target names: 0 -> No Disease, 1 -> Disease
print(classification_report(y_test, y_pred, target_names=["No Disease", "Disease"]))

# Confusion Matrix
print("Confusion Matrix:")
cm = confusion_matrix(y_test, y_pred)
print(cm)
print("\nPlotting confusion matrix...")

# Plotting the confusion matrix for better visualization
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='g', cmap='Blues',
            xticklabels=["No Disease", "Disease"],
            yticklabels=["No Disease", "Disease"])
plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.title("Confusion Matrix")
plt.show()

print("\nEvaluation complete.")
