import os
from llm.gemini_client import get_gemini_client

def get_groq_client():
    # Production validation path now redirects to Gemini
    return get_gemini_client()

