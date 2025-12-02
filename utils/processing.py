import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import pickle
import os

# --- Define File Paths ---
# This script is in the utils folder, so paths are relative to the main project root.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "heart.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "heart_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")


# --- Load Dataset ---
print("--- Loading dataset...")
try:
    # Column names are based on the UCI dataset documentation.
    col_names = ['age', 'sex', 'cp', 'trestbps', 'chol', 'fbs', 'restecg', 'thalach',
                 'exang', 'oldpeak', 'slope', 'ca', 'thal', 'target']
    df = pd.read_csv(DATA_PATH, header=None, names=col_names)
except FileNotFoundError:
    print(f"Error: The file {DATA_PATH} was not found.")
    print("Please make sure the 'heart.csv' dataset is in the 'HEART_DISEASE_PREDICTOR/data/' directory.")
    exit()

print("Dataset loaded successfully.")

# --- Data Cleaning and Preprocessing ---
print("--- Preprocessing data...")

# The original dataset uses '?' for missing values in some versions. This code handles that.
df.replace('?', pd.NA, inplace=True)
df.dropna(inplace=True)

# Convert all columns to numeric types
for col in df.columns:
    df[col] = pd.to_numeric(df[col], errors='coerce')

# Drop any rows that couldn't be converted
df.dropna(inplace=True)

# The target variable is named 'target'.
# A value of 0 means no heart disease, and values > 0 mean presence of heart disease.
# We convert it to a simple binary (0 or 1) classification problem.
df['target'] = df['target'].apply(lambda x: 1 if x > 0 else 0)

# Separate features (X) and target (y)
X = df.drop('target', axis=1)
y = df['target']

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"Data split into {len(X_train)} training and {len(X_test)} testing samples.")

# Scale the features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("Features have been scaled.")

# --- Model Training ---
print("--- Training the Random Forest model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=5)
model.fit(X_train_scaled, y_train)
print("Model training complete.")

# --- Model Evaluation (for our reference) ---
y_pred = model.predict(X_test_scaled)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy on Test Set: {accuracy:.4f}")

# --- Save the Model and Scaler ---
# Create the model directory if it doesn't exist
os.makedirs(MODEL_DIR, exist_ok=True)

print(f"--- Saving model to '{MODEL_PATH}'...")
with open(MODEL_PATH, 'wb') as model_file:
    pickle.dump(model, model_file)

print(f"--- Saving scaler to '{SCALER_PATH}'...")
with open(SCALER_PATH, 'wb') as scaler_file:
    pickle.dump(scaler, scaler_file)

print("\n✅ Model and scaler have been saved successfully!")
print("You are now ready to run the Streamlit app.")

