
import os
from pathlib import Path
from dotenv import load_dotenv
from google import genai

# Always load .env from the folder containing this script
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(env_path, override=True)

api_key = os.getenv("GEMINI_API_KEY")
model = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")

if not api_key:
    raise SystemExit(
        f"ERROR: GEMINI_API_KEY not found. Checked: {env_path}"
    )

client = genai.Client(api_key=api_key)

try:
    response = client.models.generate_content(
        model=model,
        contents="In one sentence, explain what an AWS VPC is."
    )
    print("Gemini API connection successful!")
    print("Model:", model)
    print("Response:", response.text)
except Exception as error:
    print("Gemini API test failed.")
    print(type(error).__name__ + ":", error)
