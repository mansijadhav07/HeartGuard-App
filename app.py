import streamlit as st
import pandas as pd
import numpy as np
import pickle
from io import BytesIO
import os
import matplotlib.pyplot as plt
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch

# --- NEW: Database Imports ---
from database_utils import register_user, verify_user, save_prediction, get_prediction_history
import json 
# -----------------------------

# --- Page Configuration ---
st.set_page_config(page_title="HeartGuard", page_icon="❤️", layout="wide")

# ==========================================
# 🚀 PERFORMANCE FIX: CACHED MODEL LOADING
# ==========================================
@st.cache_resource
def load_model_resources():
    """
    Loads the model and scaler only ONCE.
    Streamlit will keep these in memory for super-fast access.
    """
    try:
        # Get the absolute path to ensure it works on the Cloud
        base_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(base_dir, 'model', 'heart_model.pkl')
        scaler_path = os.path.join(base_dir, 'model', 'scaler.pkl')

        with open(model_path, 'rb') as model_file:
            model = pickle.load(model_file)
        with open(scaler_path, 'rb') as scaler_file:
            scaler = pickle.load(scaler_file)
        return model, scaler
    except Exception as e:
        return None, e

# Load them now
model, scaler = load_model_resources()

# Check if loading failed
if model is None:
    st.error(f"CRITICAL ERROR: Could not load model files.")
    st.error(f"Details: {scaler}") # 'scaler' variable holds the error message here
    st.info("Did you upload the 'model/' folder to GitHub?")
    st.stop()

# ==========================================
# END OF PERFORMANCE FIX
# ==========================================


# --- Custom CSS for Styling ---
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');
@import url('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css');

body {
    font-family: 'Roboto', sans-serif;
    background-color: #f4f7f9;
    margin: 0;
    padding: 0;
}

/* Hide Streamlit Header, Footer, Toolbar */
#MainMenu, footer, .stToolbar {
    visibility: hidden;
}

/* Hero Section */
.hero-section {
    padding: 5rem 2rem;
    text-align: center;
    background: linear-gradient(135deg, #ff758c 0%, #ff7eb3 100%);
    border-radius: 25px;
    margin-bottom: 3rem;
    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
    transition: transform 0.3s ease;
    min-height: 500px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
}

.hero-section:hover {
    transform: translateY(-5px);
}
.hero-section .icon {
    font-size: 7rem;
    color: #fff;
    animation: pulse 2s infinite;
}
@keyframes pulse {
    0%, 100% { transform: scale(1); }
    50% { transform: scale(1.2); }
}
.hero-section h1 {
    font-size: 4.5rem;
    font-weight: 800;
    color: white;
    text-shadow: 2px 2px 8px rgba(0,0,0,0.2);
}
.hero-section p {
    font-size: 1.3rem;
    color: #fff;
    max-width: 700px;
    margin: 1rem auto;
}

/* Buttons */
.stButton>button {
    font-weight: 700;
    border-radius: 50px;
    padding: 16px 40px;
    border: none;
    font-size: 1.1rem;
    color: white;
    font-weight:bold;
    background-color: #ff4b5c;
    box-shadow: 0 6px 20px rgba(255,117,140,0.4);
    transition: all 0.3s ease;
    cursor: pointer;
    text-transform: uppercase;
    letter-spacing: 1px;
    position: relative;
    overflow: hidden;
}

.stButton>button:hover {
    transform: translateY(-4px) scale(1.05);
    box-shadow: 0 12px 25px rgba(255,117,140,0.6);
    color: black;
}

.stButton>button::after {
    content: '';
    position: absolute;
    top: 0;
    left: -75%;
    width: 50%;
    height: 100%;
    background: rgba(255,255,255,0.3);
    transform: skewX(-25deg);
    transition: all 0.5s;
}
.stButton>button:hover::after {
    left: 125%;
}

.primary-button button {
    background-color: #007BFF;
    color: white;
}
.primary-button button:hover {
    background-color: #0056b3;
}
.secondary-button button {
    background-color: #ffffff;
    color: #007BFF;
    border: 2px solid #007BFF;
}
.secondary-button button:hover {
    background-color: #f0f8ff;
}

/* Stats Section */
.stats-section {
    display: flex;
    justify-content: space-around;
    text-align: center;
    padding: 2rem 0;
}
.stat-item h2 {
    font-size: 2.8rem;
    color: #ff4b5c;
    font-weight: 700;
}
.stat-item p {
    font-size: 1rem;
    color: #555;
}

/* Section Containers */
.section-container {
    text-align: center;
    padding: 3rem 1rem;
}
.section-container h2 {
    font-size: 2.8rem;
    font-weight: 700;
    margin-bottom: 1rem;
}
.section-container .subtitle {
    color: #666;
    margin-bottom: 3rem;
    max-width: 700px;
    margin-left: auto;
    margin-right: auto;
}

/* Feature Cards */
.feature-cards {
    display: flex;
    justify-content: center;
    gap: 2rem;
    flex-wrap: wrap;
}
.feature-card {
    background: linear-gradient(145deg, #e0f7fa, #ffffff);
    padding: 2rem;
    border-radius: 20px;
    width: 260px;
    text-align: center;
    box-shadow: 0 10px 25px rgba(0,0,0,0.05);
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}
.feature-card:hover {
    transform: translateY(-10px);
    box-shadow: 0 15px 35px rgba(0,0,0,0.1);
}
.feature-card .icon {
    font-size: 3rem;
    color: #ff4b5c;
    margin-bottom: 1rem;
    transition: transform 0.3s ease, color 0.3s ease;
}
.feature-card:hover .icon {
    transform: scale(1.2);
    color: #ff758c;
}
.feature-card h3 {
    font-size: 1.4rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
}
.feature-card p {
    color: #555;
}

/* Form Section */
.form-section-container {
    background: linear-gradient(135deg, #f0f8ff, #ffffff);
    padding: 2.5rem;
    border-radius: 20px;
    box-shadow: 0 10px 25px rgba(0,0,0,0.05);
    margin-bottom: 2rem;
}
.stNumberInput>div>input, .stSelectbox>div>select {
    border-radius: 15px !important;
    border: 1px solid #ddd !important;
    padding: 10px !important;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
}

/* How It Works Steps */
.how-it-works-step .step-number {
    font-size: 4rem;
    font-weight: 700;
    color:#ff4b5c;
}
.how-it-works-step h3 {
    font-size: 1.5rem;
    font-weight: 700;
    margin-top: -1.5rem;
}

/* CTA Section */
.cta-section {
    background-color: #e0f7fa;
    padding: 3rem;
    border-radius: 25px;
    text-align: center;
    margin-top: 3rem;
    box-shadow: 0 8px 20px rgba(0,0,0,0.05);
}

/* Footer */
.footer {
    text-align: center;
    padding: 2rem 0;
    color: #888;
    font-size: 0.9rem;
}

/* Results Card */
.result-card {
    border-radius: 20px;
    padding: 2rem;
    box-shadow: 0 8px 20px rgba(0,0,0,0.05);
    margin-bottom: 1.5rem;
    text-align: center;
    transition: transform 0.3s ease;
}
.result-card.high-risk {
    background: linear-gradient(135deg, #ffdde1, #ff4b5c);
    color: white;
}
.result-card.low-risk {
    background: linear-gradient(135deg, #d4edda, #28a745);
    color: white;
}

/* Progress Bar */
.progress-bar {
    height: 18px;
    border-radius: 10px;
    background: #ddd;
    overflow: hidden;
    margin-top: 1rem;
}
.progress-fill {
    height: 100%;
    background: #007BFF;
    text-align: right;
    padding-right: 8px;
    color: white;
    font-weight: bold;
    border-radius: 10px;
    transition: width 0.6s ease;
}
/* Typewriter Animation */
.hero-section h1 {
    display: inline-block;
    font-size: 4.5rem;
    font-weight: 800;
    color: white;
    text-shadow: 2px 2px 8px rgba(0,0,0,0.2);
}

.typewriter-wrapper {
    display: flex;
    justify-content: center;
    align-items: center;
}

.typewriter {
    overflow: hidden;
    border-right: .15em solid #fff;
    white-space: nowrap;
    letter-spacing: .1em;
    animation: typing 1s steps(12, end),
               blink-caret .75s step-end infinite,
               gradient-move 3s linear infinite;
}

@keyframes typing {
    from { width: 0 }
    to { width: 12ch }
}

@keyframes blink-caret {
    from, to { border-color: transparent }
    50% { border-color: #fff; }
}

/* --- Sidebar and Navigation Styles (Professional UI) --- */
/* Target the main sidebar container */
.css-1d391kg { 
    background-color: #f8f9fa; /* Light background for contrast */
    padding: 1rem 0.5rem;
    box-shadow: 2px 0 10px rgba(0,0,0,0.05);
}
/* Title styling */
.sidebar-title {
    font-size: 1.5rem;
    font-weight: 700;
    color: #ff4b5c; /* Your primary color */
    padding: 1rem 0;
    border-bottom: 2px solid #ff4b5c;
    margin-bottom: 1.5rem;
    text-align: center;
}

/* Custom button styling for sidebar links */
.stButton>button {
    font-weight: 500;
    border-radius: 8px;
    padding: 10px 15px;
    margin-bottom: 8px;
    border: 1px solid #ddd;
    background-color: white;
    color: #333;
    transition: all 0.2s ease;
    text-transform: none; /* Remove uppercase for clean look */
    letter-spacing: normal;
    box-shadow: none; /* Remove heavy shadow */
}
/* Sidebar button hover/active effect */
.stButton>button:hover {
    background-color: #ffe0e6; /* Light pink background on hover */
    color: #ff4b5c; /* Text color change on hover */
    border-color: #ff4b5c;
    transform: none; /* Remove transform/scale effect for sidebar */
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}
/* Status box styling */
.stAlert {
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)


# --- Helper Functions ---
def generate_pdf_report(data, prediction_text, probability):
    """Generates a downloadable PDF report."""
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(width / 2.0, height - 1 * inch, "❤️ HeartGuard Health Report")

    c.setFont("Helvetica", 12)
    text = c.beginText(1 * inch, height - 2 * inch)
    text.textLine("Patient Health Data:")
    # Recreate the user-friendly labels for the PDF
    display_data = {
        'Age': data.get('age'),
        'Sex': "Male" if data.get('sex') == 1 else "Female",
        'Chest Pain Type': ["Typical Angina", "Atypical Angina", "Non-anginal Pain", "Asymptomatic"][data.get('cp')],
        'Resting Blood Pressure': f"{data.get('trestbps')} mm Hg",
        'Serum Cholesterol': f"{data.get('chol')} mg/dl",
        'Fasting Blood Sugar > 120 mg/dl': "Yes" if data.get('fbs') == 1 else "No",
        'Resting ECG Results': ["Normal", "ST-T wave abnormality", "Left ventricular hypertrophy"][data.get('restecg')],
        'Maximum Heart Rate Achieved': data.get('thalach'),
        'Exercise Induced Angina': "Yes" if data.get('exang') == 1 else "No",
        'ST Depression': data.get('oldpeak'),
        'Peak Exercise ST Slope': ["Upsloping", "Flat", "Downsloping"][data.get('slope')],
        'Major Vessels Colored': data.get('ca'),
        'Thalassemia': ["Normal", "Fixed defect", "Reversible defect"][(data.get('thal', 1)-1)],
    }
    for key, value in display_data.items():
        text.textLine(f"  - {key}: {value}")
    c.drawText(text)

    c.setFont("Helvetica-Bold", 14)
    if "High Risk" in prediction_text:
        c.setFillColorRGB(0.8, 0, 0)
    else:
        c.setFillColorRGB(0, 0.6, 0)
    c.drawCentredString(width / 2.0, height - 5 * inch, prediction_text)
    c.setFont("Helvetica", 12)
    c.setFillColorRGB(0,0,0)
    c.drawCentredString(width / 2.0, height - 5.3 * inch, f"Confidence Score: {probability:.2f}%")

    c.setFont("Helvetica-Oblique", 8)
    c.drawString(1 * inch, 1 * inch, "This report is for educational purposes only and not a substitute for professional medical advice.")
    c.save()
    buffer.seek(0)
    return buffer

# --- App State Management (Corrected for Auth) ---
if 'page' not in st.session_state:
    st.session_state.page = 'login' # Default page is now login/signup
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'username' not in st.session_state:
    st.session_state.username = None

# --- NEW: Sidebar Navigation (Professional UI) ---
def setup_sidebar():
    # 1. Custom Title
    st.sidebar.markdown('<div class="sidebar-title">❤️ HeartGuard </div>', unsafe_allow_html=True)
    
    # 2. Status Indicator
    if st.session_state.logged_in:
        st.sidebar.markdown(f"""
            <div style="padding: 10px; border-radius: 8px; background-color: #d4edda; color: #155724; font-weight: bold; margin-bottom: 20px; text-align: center;">
                <i class="fas fa-user-check"></i> Logged in as: {st.session_state.username}
            </div>
        """, unsafe_allow_html=True)
    else:
        st.sidebar.markdown("""
            <div style="padding: 10px; border-radius: 8px; background-color: #f8d7da; color: #721c24; font-weight: bold; margin-bottom: 20px; text-align: center;">
                <i class="fas fa-exclamation-triangle"></i> Session Required
            </div>
        """, unsafe_allow_html=True)

    st.sidebar.markdown("---")
    
    # 3. Primary Navigation
    st.sidebar.subheader("Navigation")
    
    if st.sidebar.button("🏠 Home"):
        st.session_state.page = 'home'
        st.rerun()

    if st.session_state.logged_in:
        
        if st.sidebar.button("🔬 Start New Assessment"):
            st.session_state.page = 'assessment'
            st.rerun()

        if st.sidebar.button("📜 View History"):
            st.session_state.page = 'history'
            st.rerun()
            
        st.sidebar.markdown("---")
        
        # 4. Logout Button (Styled as a distinct action)
        st.sidebar.subheader("Account")
        if st.sidebar.button("➡️ Logout", key="logout_btn"):
            # Clear session state variables
            st.session_state.logged_in = False
            st.session_state.user_id = None
            st.session_state.username = None
            st.session_state.page = 'login' 
            st.success("You have been logged out.")
            st.rerun()
            
    else:
        # 5. Auth Buttons for Not Logged In
        st.sidebar.subheader("Access")
        if st.sidebar.button("🔑 Login"):
            st.session_state.page = 'login'
            st.rerun()
        if st.sidebar.button("📝 Sign Up"):
            st.session_state.page = 'signup'
            st.rerun()

# Call the sidebar function after st.set_page_config
setup_sidebar()
# ----------------------------------


# --- Page Rendering Functions ---
def render_home_page():
    # Hero Section
    st.markdown("""
        <div class="hero-section">
            <div class="icon">❤️</div>
            <div class="typewriter-wrapper">
    <h1 class="typewriter">HeartGuard</h1>
</div>
            <p>AI-Powered Heart Disease Detection System</p>
            <p style="margin-top:1rem;">Advanced machine learning technology for rapid, accurate cardiovascular risk assessment using comprehensive patient health data.</p>
        </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1.5, 2, 1.5])
    with col2:
        st.markdown('<div class="primary-button">', unsafe_allow_html=True)
        if st.session_state.logged_in:
            if st.button("❤️ Start Assessment", use_container_width=True):
                st.session_state.page = 'assessment'
                st.rerun()
        else:
            if st.button("🔑 Login to Start Assessment", use_container_width=True):
                st.session_state.page = 'login'
                st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)


    # Stats Section
    st.markdown("""
        <div class="stats-section">
            <div class="stat-item"><h2>95%</h2><p>Accuracy</p></div>
            <div class="stat-item"><h2>10K+</h2><p>Assessments</p></div>
            <div class="stat-item"><h2>&lt;2s</h2><p>Response Time</p></div>
        </div>
    """, unsafe_allow_html=True)

    # Why Choose Us Section
    st.markdown("""
        <div class="section-container">
            <h2>Why Choose HeartGuard?</h2>
            <p class="subtitle">Cutting-edge AI technology combined with evidence-based medical research.</p>
            <div class="feature-cards">
                <div class="feature-card">
                    <div class="icon"><i class="fas fa-brain"></i></div>
                    <h3>AI-Powered Analysis</h3>
                    <p>Advanced machine learning algorithms trained on clinical data.</p>
                </div>
                <div class="feature-card">
                    <div class="icon"><i class="fas fa-bolt"></i></div>
                    <h3>Instant Results</h3>
                    <p>Get comprehensive risk assessment in seconds.</p>
                </div>
                <div class="feature-card">
                    <div class="icon"><i class="fas fa-chart-pie"></i></div>
                    <h3>Detailed Insights</h3>
                    <p>Visualize key factors affecting your heart health.</p>
                </div>
                <div class="feature-card">
                    <div class="icon"><i class="fas fa-shield-alt"></i></div>
                    <h3>Evidence-Based</h3>
                    <p>Based on Cleveland Heart Disease dataset standards.</p>
                </div>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # How It Works Section
    st.markdown("""
        <div class="section-container" style="background-color: #f8f9fa; border-radius: 20px;">
            <h2>How It Works</h2>
            <p class="subtitle">Simple, fast, and accurate heart disease risk assessment in three steps.</p>
        </div>
    """, unsafe_allow_html=True)
    
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""
            <div class="how-it-works-step">
                <div class="step-number">01</div>
                <h3>Input Patient Data</h3>
                <p>Enter comprehensive health metrics including vital signs, ECG results, and exercise test data.</p>
            </div>
        """, unsafe_allow_html=True)
    with c2:
        st.markdown("""
            <div class="how-it-works-step">
                <div class="step-number">02</div>
                <h3>AI Analysis</h3>
                <p>Advanced machine learning model processes your data using Cleveland Heart Disease dataset patterns.</p>
            </div>
        """, unsafe_allow_html=True)
    with c3:
        st.markdown("""
            <div class="how-it-works-step">
                <div class="step-number">03</div>
                <h3>Get Results</h3>
                <p>Receive detailed risk assessment with visualizations and personalized recommendations.</p>
            </div>
        """, unsafe_allow_html=True)

    # CTA Section
    st.markdown("""
        <div class="cta-section">
            <h2>Ready to Check Your Heart Health?</h2>
            <p>Take the first step towards understanding your cardiovascular risk with our AI-powered assessment tool.</p>
        </div>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([2, 1.5, 2])
    with col2:
        st.markdown('<div class="primary-button" style="margin-top: 3rem;">', unsafe_allow_html=True)
        if st.button("Start Free Assessment", use_container_width=True, key="cta_button"):
            st.session_state.page = 'assessment'
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

    # Footer
    st.markdown("""
        <div class="footer">
            <p>Educational Purpose Only - Not a substitute for professional medical advice.</p>
            <p>© 2025 HeartGuard. All Rights Reserved.</p>
        </div>
    """, unsafe_allow_html=True)

def render_assessment_page():
    st.markdown("""
    <style>
    /* Floating heart background */
    @keyframes float {
        0% { transform: translateY(0) rotate(0deg); opacity: 0.7; }
        50% { transform: translateY(-50px) rotate(180deg); opacity: 0.9; }
        100% { transform: translateY(-100px) rotate(360deg); opacity: 0; }
    }
    .floating-heart {
        position: fixed;
        font-size: 2rem;
        color: #ff4b5c;
        animation: float 5s linear infinite;
        opacity: 0.8;
        z-index: 0;
    }

    /* Form section styling */
    .form-section {
        background: linear-gradient(135deg, #fdfbfb, #ebedee);
        padding: 30px;
        border-radius: 25px;
        box-shadow: 0 15px 35px rgba(0,0,0,0.08);
        margin-bottom: 25px;
        transition: transform 0.3s ease, box-shadow 0.3s ease;
        position: relative;
        z-index: 1;
    }
    .form-section:hover {
        transform: translateY(-8px);
        box-shadow: 0 25px 50px rgba(0,0,0,0.15);
    }
    .form-section h2 {
        color: #ff4b5c;
        font-size: 2rem;
        margin-bottom: 15px;
        text-align: center;
    }

    /* Input styling */
    .stNumberInput>div>input, .stSelectbox>div>select {
        border-radius: 15px !important;
        border: 1px solid #ddd !important;
        padding: 12px !important;
        box-shadow: 0 4px 15px rgba(0,0,0,0.05);
        transition: all 0.3s ease;
    }
    .stNumberInput>div>input:focus, .stSelectbox>div>select:focus {
        border-color: #ff4b5c !important;
        box-shadow: 0 4px 15px rgba(255,75,92,0.3);
        outline: none;
    }

    /* Submit button */
    .stButton>button {
        background: linear-gradient(135deg, #ff4b5c, #ff758c);
        color: white;
        font-weight: 700;
        border-radius: 50px;
        padding: 16px 45px;
        font-size: 1.2rem;
        box-shadow: 0 8px 25px rgba(255,75,92,0.4);
        transition: all 0.3s ease;
        display: block;
        margin: auto;
    }
    .stButton>button:hover {
        transform: translateY(-5px) scale(1.05);
        box-shadow: 0 15px 35px rgba(255,75,92,0.6);
        cursor: pointer;
    }

    /* Floating hearts behind form */
    </style>
    <div class="floating-heart" style="left:10%; animation-delay:0s;">❤️</div>
    <div class="floating-heart" style="left:30%; animation-delay:2s;">❤️</div>
    <div class="floating-heart" style="left:50%; animation-delay:1s;">❤️</div>
    <div class="floating-heart" style="left:70%; animation-delay:3s;">❤️</div>
    <div class="floating-heart" style="left:90%; animation-delay:1.5s;">❤️</div>
    """, unsafe_allow_html=True)

    st.markdown('<h1 style="text-align: center;">❤️ Heart Health Assessment</h1>', unsafe_allow_html=True)
    st.markdown("<p style='text-align:center; font-size:1.2rem; color:#555;'>Provide accurate patient data for reliable AI-powered assessment</p>", unsafe_allow_html=True)

    with st.form("assessment_form"):

        # Patient Information
        st.markdown('<div class="form-section"><h2>Patient Information</h2></div>', unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            age = st.number_input("Age", 1, 120, 50)
        with col2:
            sex = st.selectbox("Sex", ("Male", "Female"))
        cp = st.selectbox("Chest Pain Type", ("Typical Angina", "Atypical Angina", "Non-anginal Pain", "Asymptomatic"))

        # Clinical Measurements
        st.markdown('<div class="form-section"><h2>Clinical Measurements</h2></div>', unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            trestbps = st.number_input("Resting Blood Pressure (mm Hg)", 90, 200, 120)
            fbs = st.selectbox("Fasting Blood Sugar > 120 mg/dl", ("No", "Yes"))
        with col2:
            chol = st.number_input("Serum Cholesterol (mg/dl)", 100, 600, 200)
            restecg = st.selectbox("Resting ECG Results", ("Normal", "ST-T wave abnormality", "Left ventricular hypertrophy"))

        # Exercise Test Data
        st.markdown('<div class="form-section"><h2>Exercise Test Data</h2></div>', unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            thalach = st.number_input("Max Heart Rate Achieved", 60, 220, 150)
            oldpeak = st.number_input("ST Depression induced by exercise", 0.0, 6.2, 1.0)
            ca = st.selectbox("Major vessels colored by fluoroscopy", (0, 1, 2, 3, 4))
        with col2:
            exang = st.selectbox("Exercise Induced Angina", ("No", "Yes"))
            slope = st.selectbox("Peak exercise ST segment slope", ("Upsloping", "Flat", "Downsloping"))
            thal = st.selectbox("Thalassemia", ("Normal", "Fixed defect", "Reversible defect"))

        
        submitted = st.form_submit_button("Get Risk Assessment")

        if submitted:
            # --- CORRECTED: Input Data and Preprocessing Logic (Fixing Pylance errors) ---
            input_data = {
                'age': age, 'sex': 1 if sex=="Male" else 0,
                'cp': ["Typical Angina","Atypical Angina","Non-anginal Pain","Asymptomatic"].index(cp),
                'trestbps': trestbps, 'chol': chol, 'fbs': 1 if fbs=="Yes" else 0,
                'restecg': ["Normal","ST-T wave abnormality","Left ventricular hypertrophy"].index(restecg),
                'thalach': thalach, 'exang': 1 if exang=="Yes" else 0, 'oldpeak': oldpeak,
                'slope': ["Upsloping","Flat","Downsloping"].index(slope),
                'ca': ca, 'thal': ["Normal","Fixed defect","Reversible defect"].index(thal)+1
            }
            feature_order = ['age','sex','cp','trestbps','chol','fbs','restecg','thalach','exang','oldpeak','slope','ca','thal']
            input_df = pd.DataFrame([input_data])[feature_order]
            scaled_features = scaler.transform(input_df)
            # -----------------------------------------------------------------------------

            prediction = model.predict(scaled_features)[0]
            probability = model.predict_proba(scaled_features)[0][prediction]*100

            # --- NEW: SAVE PREDICTION TO DATABASE ---
            if st.session_state.logged_in:
                save_prediction(
                    user_id=st.session_state.user_id, 
                    input_data=input_data, 
                    prediction=int(prediction), 
                    probability=float(probability)
                )
            # ----------------------------------------

            st.session_state.prediction = prediction
            st.session_state.probability = probability
            st.session_state.input_data = input_data
            st.session_state.page = 'results'
            st.rerun()


def render_results_page():
    prediction = st.session_state.get('prediction')
    probability = st.session_state.get('probability')
    input_data = st.session_state.get('input_data')

    if prediction is None:
        st.warning("Please complete the assessment first.")
        if st.button("Start Assessment"):
            st.session_state.page = 'assessment'
            st.rerun()
        return
    
    st.markdown('<h1 style="text-align: center;">❤️ Your Heart Health Results</h1>', unsafe_allow_html=True)

    col1, col2 = st.columns([1.5, 1])
    with col1:
        st.header("Risk Assessment")  
        if prediction == 1:
            prediction_text = "High Risk of Heart Disease"
            st.error(f"⚠️ {prediction_text} (Confidence: {probability:.1f}%)")
            st.markdown("Your results suggest a significant likelihood. It is **crucial** to consult with a healthcare provider for a detailed evaluation and guidance.")
        else:
            prediction_text = "Low Risk of Heart Disease"
            st.success(f"✅ {prediction_text} (Confidence: {probability:.1f}%)")
            st.markdown("Your results suggest a lower likelihood. Continue to maintain a healthy lifestyle and have regular check-ups.")
        
        # Display key input data
        st.subheader("Summary of Your Data")
        c1, c2 = st.columns(2)
        c1.metric("Age", f"{input_data['age']} years")
        c2.metric("Sex", "Male" if input_data['sex']==1 else "Female")
        c1.metric("Blood Pressure", f"{input_data['trestbps']} mm Hg")
        c2.metric("Cholesterol", f"{input_data['chol']} mg/dl")
        c1.metric("Max Heart Rate", f"{input_data['thalach']} bpm")
        
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.header("Recommendations")
        st.info("Consult a healthcare provider for a detailed assessment.")
        st.info("Increase physical activity under medical guidance.")
        st.info("Adopt a heart-healthy diet (e.g., Mediterranean).")
        st.info("Monitor blood pressure and cholesterol regularly.")
        st.warning("**Disclaimer:** This is an educational tool, not a substitute for professional medical advice.")
        st.markdown('</div>', unsafe_allow_html=True)

    # Action Buttons
    st.markdown("---")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown('<div class="primary-button">', unsafe_allow_html=True)
        if st.button("New Assessment", use_container_width=True):
            st.session_state.page = 'assessment'
            # Clear previous results
            for key in ['prediction', 'probability', 'input_data']:
                if key in st.session_state:
                    del st.session_state[key]
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)
    with c2:
         pdf_report = generate_pdf_report(input_data, prediction_text, probability)
         st.markdown('<div class="secondary-button">', unsafe_allow_html=True)
         st.download_button(
             label="Download PDF Report",
             data=pdf_report,
             file_name="HeartGuard_Report.pdf",
             mime="application/pdf",
             use_container_width=True
         )
         st.markdown('</div>', unsafe_allow_html=True)

    with c3:
        st.markdown('<div class="secondary-button">', unsafe_allow_html=True)
        if st.button("Back to Home", use_container_width=True):
            st.session_state.page = 'home'
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)

# --- NEW: Authentication Page Rendering Functions ---
def render_login_page():
    st.markdown('<h1 style="text-align: center;">🔑 Welcome to HeartGuard</h1>', unsafe_allow_html=True)
    st.markdown("<p style='text-align:center;'>Please log in to access your personal assessment tool and history.</p>", unsafe_allow_html=True)
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            user_id = verify_user(username, password)
            if user_id:
                st.session_state.logged_in = True
                st.session_state.user_id = user_id
                st.session_state.username = username 
                st.success(f"Welcome back, {username}! Redirecting to Home...")
                st.session_state.page = 'home'
                st.rerun()
            else:
                st.error("Invalid username or password.")
                
    st.markdown("---")
    if st.button("Need an account? Sign Up Here"):
        st.session_state.page = 'signup'
        st.rerun()

def render_signup_page():
    st.markdown('<h1 style="text-align: center;">📝 Create a New Account</h1>', unsafe_allow_html=True)
    st.markdown("<p style='text-align:center;'>Protect your data with a secure username and password.</p>", unsafe_allow_html=True)
    
    with st.form("signup_form"):
        new_username = st.text_input("Choose a Username (4+ characters)")
        new_password = st.text_input("Choose a Password (6+ characters)", type="password")
        confirm_password = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register Account")

        if submitted:
            if new_password != confirm_password:
                st.error("Passwords do not match.")
            elif len(new_username) < 4 or len(new_password) < 6:
                st.error("Username must be at least 4 characters and password at least 6 characters.")
            else:
                success, message = register_user(new_username, new_password)
                if success:
                    st.success(f"{message} You can now log in.")
                    st.session_state.page = 'login'
                    st.rerun()
                else:
                    st.error(message)

    st.markdown("---")
    if st.button("Already have an account? Go to Login"):
        st.session_state.page = 'login'
        st.rerun()

def render_history_page():
    st.markdown('<h1 style="text-align: center;">🕰️ Your Prediction History</h1>', unsafe_allow_html=True)

    if not st.session_state.logged_in:
        st.error("⚠️ Access Denied. Please log in to view your history.")
        return

    history_df = get_prediction_history(st.session_state.user_id)

    if history_df.empty:
        st.info("You have no past assessment results yet. Start a new assessment to save your first record!")
    else:
        st.subheader(f"Assessment History for {st.session_state.username}")
        
        # Process and display the DataFrame
        history_df['Date & Time'] = pd.to_datetime(history_df['timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S')
        history_df['Risk Level'] = history_df['prediction'].apply(lambda x: 'High Risk 🔴' if x == 1 else 'Low Risk 🟢')
        history_df['Confidence'] = history_df['probability'].apply(lambda x: f"{x:.1f}%")
        
        # Create a more user-friendly data summary
        def format_input_data(json_str):
            try:
                # Need to handle potential single quotes from Python's str() if used previously
                data = json.loads(json_str.replace("'", "\"")) 
                return f"Age: {data.get('age')}, Sex: {'M' if data.get('sex') == 1 else 'F'}, BP: {data.get('trestbps')}, Chol: {data.get('chol')}"
            except:
                return "Full data available in raw view"


        history_df['Quick Summary'] = history_df['input_data'].apply(format_input_data)

        # Display the table
        st.dataframe(
            history_df[['Date & Time', 'Risk Level', 'Confidence', 'Quick Summary']], 
            column_config={
                "Quick Summary": st.column_config.Column(
                    "Input Data Summary",
                    width="large",
                )
            },
            hide_index=True
        )

    st.markdown("---")
    if st.button("Start New Assessment"):
        st.session_state.page = 'assessment'
        st.rerun()
# ----------------------------------------------------


# --- Main App Router (Unified and Correct) ---
if st.session_state.page == 'login':
    render_login_page()
elif st.session_state.page == 'signup':
    render_signup_page()
elif st.session_state.page == 'home':
    render_home_page()
elif st.session_state.page == 'history':
    render_history_page()
elif st.session_state.page == 'assessment':
    # Ensure user is logged in before allowing assessment
    if st.session_state.logged_in:
        render_assessment_page()
    else:
        st.session_state.page = 'login'
        st.warning("Please log in to start an assessment.")
        st.rerun()
elif st.session_state.page == 'results':
    render_results_page()
# ---------------------------------------------