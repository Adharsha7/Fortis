from flask import Flask, jsonify, make_response
import jwt

app = Flask(__name__)

# Weak secret intentionally
SECRET_KEY = "weaksecret"

@app.route("/")
def home():
    return """
    <html>
    <head>
        <title>Vulnerable Demo App</title>
    </head>
    <body>
        <h2>Demo Vulnerable Application</h2>

        <!-- 🚨 Insecure JWT stored in localStorage -->
        <script>
            localStorage.setItem("token", "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.");
        </script>

        <!-- 🚨 Fake OpenAI API Key exposed -->
        <script>
            const apiKey = "sk-test12345678901234567890";
        </script>

        <p>This app intentionally contains vulnerabilities for testing.</p>
    </body>
    </html>
    """


# 🚨 JWT without expiry
@app.route("/generate-token")
def generate_token():
    payload = {
        "user": "admin"
        # No "exp" field intentionally
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return jsonify({"token": token})


# 🚨 Fake exposed .env file
@app.route("/.env")
def env_file():
    content = """
DB_PASSWORD=test123
API_KEY=abcdef123456
SECRET_KEY=supersecret
"""
    response = make_response(content)
    response.headers["Content-Type"] = "text/plain"
    return response


if __name__ == "__main__":
    app.run(debug=True)