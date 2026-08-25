import os
from dotenv import load_dotenv
load_dotenv('.env')

from openai import OpenAI

api_key = os.getenv("GROQ_API_KEY")
client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")

try:
    response = client.chat.completions.create(
        model="openai/gpt-oss-120b",
        messages=[{"role": "user", "content": "Hello"}],
    )
    print(response.choices[0].message.content)
except Exception as e:
    print(f"Error: {e}")
