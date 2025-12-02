# ==========================================================
# FILE: database_utils.py (PostgreSQL / Supabase Version)
# ==========================================================
import streamlit as st
import psycopg2
from bcrypt import hashpw, gensalt, checkpw
import pandas as pd
import json
import os

# Function to get a database connection
# Function to get a database connection
def get_connection():
    try:
        # CORRECT: Ask for the secret by its NAME ("DATABASE_URL")
        db_url = st.secrets["DATABASE_URL"]
        return psycopg2.connect(db_url)
    except Exception as e:
        st.error(f"Connection Error: {e}")
        return None

def init_db():
    """Initializes the PostgreSQL tables if they don't exist."""
    conn = get_connection()
    if not conn:
        return
        
    try:
        c = conn.cursor()
        
        # 1. Users Table
        # Note: SERIAL is used in Postgres for auto-incrementing IDs
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash BYTEA NOT NULL
            );
        ''')

        # 2. Predictions History Table
        c.execute('''
            CREATE TABLE IF NOT EXISTS predictions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                input_data TEXT, 
                prediction INTEGER,
                probability REAL
            );
        ''')
        
        conn.commit()
    except Exception as e:
        st.error(f"DB Init Error: {e}")
    finally:
        conn.close()

# --- User Authentication Functions ---

def register_user(username, password):
    """Adds a new user to the database after securely hashing the password."""
    conn = get_connection()
    if not conn:
        return False, "Database connection failed."
        
    try:
        c = conn.cursor()
        # Hash the password using bcrypt
        password_bytes = password.encode('utf-8')
        hashed_password = hashpw(password_bytes, gensalt())
        
        # Postgres syntax uses %s for placeholders
        c.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", 
                  (username, hashed_password))
        conn.commit()
        return True, "Registration successful!"
    except psycopg2.IntegrityError:
        conn.rollback() # Necessary in Postgres after an error
        return False, "Username already exists."
    except Exception as e:
        conn.rollback()
        return False, f"An error occurred: {e}"
    finally:
        conn.close()

def verify_user(username, password):
    """Verifies a user's credentials and returns their ID."""
    conn = get_connection()
    if not conn:
        return None
        
    try:
        c = conn.cursor()
        c.execute("SELECT id, password_hash FROM users WHERE username = %s", (username,))
        result = c.fetchone()
        
        if result:
            user_id, stored_hash = result
            # Postgres returns BYTEA (bytes), which is what checkpw needs
            # If stored_hash is memoryview (sometimes happens), convert to bytes
            if isinstance(stored_hash, memoryview):
                stored_hash = bytes(stored_hash)
                
            if checkpw(password.encode('utf-8'), stored_hash):
                return user_id
    except Exception as e:
        st.error(f"Login Error: {e}")
    finally:
        conn.close()
        
    return None

# --- Prediction History Functions ---

def save_prediction(user_id, input_data, prediction, probability):
    """Saves a prediction result to the history table."""
    conn = get_connection()
    if not conn:
        return

    try:
        c = conn.cursor()
        input_data_json = json.dumps(input_data)
        
        c.execute("""
            INSERT INTO predictions (user_id, input_data, prediction, probability) 
            VALUES (%s, %s, %s, %s)
        """, (user_id, input_data_json, prediction, probability))
        
        conn.commit()
    except Exception as e:
        st.error(f"Save Error: {e}")
    finally:
        conn.close()

def get_prediction_history(user_id):
    """Fetches all prediction records for a given user as a DataFrame."""
    conn = get_connection()
    if not conn:
        return pd.DataFrame() # Return empty DF on failure
        
    try:
        # pandas read_sql is convenient here
        query = "SELECT timestamp, prediction, probability, input_data FROM predictions WHERE user_id = %s ORDER BY timestamp DESC"
        history_df = pd.read_sql(query, conn, params=(user_id,))
        return history_df
    except Exception as e:
        st.error(f"History Fetch Error: {e}")
        return pd.DataFrame()
    finally:
        conn.close()

# --- ADMIN FUNCTIONS (Add to database_utils.py) ---

def get_all_users_count():
    """Returns the total number of registered users."""
    conn = get_connection()
    if not conn: return 0
    try:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        return c.fetchone()[0]
    finally:
        conn.close()

def get_total_predictions_count():
    """Returns total assessments made."""
    conn = get_connection()
    if not conn: return 0
    try:
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM predictions")
        return c.fetchone()[0]
    finally:
        conn.close()

def get_risk_distribution():
    """Returns count of High Risk (1) vs Low Risk (0)."""
    conn = get_connection()
    if not conn: return 0, 0
    try:
        c = conn.cursor()
        c.execute("SELECT prediction, COUNT(*) FROM predictions GROUP BY prediction")
        rows = c.fetchall()
        # Convert to dictionary {0: count, 1: count}
        counts = {row[0]: row[1] for row in rows}
        return counts.get(1, 0), counts.get(0, 0)
    finally:
        conn.close()

def get_all_predictions_dataframe():
    """Fetches ALL prediction records for the admin table."""
    conn = get_connection()
    if not conn: return pd.DataFrame()
    try:
        # Join with users table to see WHO the patient is
        query = """
            SELECT p.timestamp, u.username, p.prediction, p.probability, p.input_data 
            FROM predictions p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.timestamp DESC
        """
        return pd.read_sql(query, conn)
    finally:
        conn.close()

# Initialize tables on first run
init_db()

