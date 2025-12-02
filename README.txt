🩺 HeartGuard — AI-Powered Heart Disease Detection System
HeartGuard is a user-friendly web application designed to predict the likelihood of heart disease based on patient health data. It leverages a machine learning model trained on the Cleveland Heart Disease dataset from the UCI Repository to provide rapid and accurate risk assessments.

The application is built with Python and Streamlit, focusing on a clean, intuitive, and professional user interface.

📂 Folder Structure
The project is organized as follows:

heartguard/
├── app.py                  # Main Streamlit application file
├── model/
│   ├── heart_model.pkl     # Trained machine learning model
│   └── scaler.pkl          # Scaler object for data normalization
├── data/
│   └── heart.csv           # Cleveland Heart Disease dataset
├── utils/
│   └── preprocessing.py    # Script to process data and train the model
├── requirements.txt        # Python dependencies
└── README.md               # This file

🚀 How to Run the Application
Follow these steps to set up and run HeartGuard on your local machine.

Step 1: Clone the Repository (or create the files)
First, ensure you have all the files in the correct folder structure as shown above.

Step 2: Install Dependencies
Open your terminal or command prompt, navigate to the heartguard root directory, and install the required Python libraries using pip:

pip install -r requirements.txt

Step 3: Train the Model
Before running the app, you need to generate the heart_model.pkl and scaler.pkl files. Run the preprocessing script from the heartguard root directory:

python utils/preprocessing.py

This will process the heart.csv data, train a Random Forest model, and save the necessary model and scaler files into the model/ directory.

Step 4: Run the Streamlit App
Once the model is trained, you can launch the web application:

streamlit run app.py

Your web browser should automatically open to the HeartGuard application, ready for use.