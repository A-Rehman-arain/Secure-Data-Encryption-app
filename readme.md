Secure Data Encryption App
🔐 A simple web app to encrypt and decrypt data securely using Python and Streamlit.

Features
User Authentication: Secure login and signup with password hashing.

Data Encryption: Encrypt and store your sensitive data with a passkey.

Data Decryption: Retrieve and decrypt your data using the passkey.

Password Hashing: User passwords are stored securely using SHA-256 hash.

Fernet Encryption: AES encryption via Fernet to encrypt and decrypt your data.

Session Handling: User session management for data safety and login persistence.

Failed Attempts Limiting: Three attempts for wrong decryption to prevent brute force.

Tech Stack
Frontend: Streamlit (Python-based UI)

Encryption: Fernet (Cryptography Library)

Backend: Python

Password Hashing: SHA-256

Installation
Follow these steps to run the app locally:

1. Clone this repository:
bash
Copy
Edit
git clone https://github.com/your-username/Secure-Data-Encryption-app.git
cd Secure-Data-Encryption-app
2. Install dependencies:
First, create a virtual environment (optional but recommended):

bash
Copy
Edit
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
Then, install the required libraries:

bash
Copy
Edit
pip install -r requirements.txt
3. Set up the .env file:
Create a .env file in the root directory.

Generate a Fernet key using the Python script and add it to the .env file.

To generate the Fernet key, run:

bash
Copy
Edit
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
Add the key to .env like this:

env
Copy
Edit
FERNET_KEY=your_generated_key_here
4. Run the app:
bash
Copy
Edit
streamlit run app.py
The app will start and be accessible on http://localhost:8501.

Usage
Login: Create a user account or log in if you already have an account.

Encrypt Data: Store your sensitive data securely by encrypting it.

Decrypt Data: Retrieve and decrypt your data by entering the correct passkey.

Logout: You can log out at any time, and your session will end.

Contributing
If you'd like to contribute to this project:

Fork the repository.

Create a new branch (git checkout -b feature-xyz).

Commit your changes (git commit -am 'Add new feature').

Push to the branch (git push origin feature-xyz).

Create a new Pull Request.

License
This project is licensed under the MIT License - see the LICENSE file for details.