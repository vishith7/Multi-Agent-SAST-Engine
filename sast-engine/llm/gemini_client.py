import os
from dotenv import load_dotenv

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# Explicitly load from the project root .env
env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".env")
load_dotenv(dotenv_path=env_path, override=True)

_client_instance = None

def get_gemini_client():
    global _client_instance
    if _client_instance is not None:
        return _client_instance
        
    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured in your .env file. "
            "Please add GEMINI_API_KEY=<your_api_key> to use the Gemini 2.5 Flash engine."
        )

    if OpenAI is None:
        raise RuntimeError("The 'openai' package is not installed.")

    base_url = os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai/")

    _client_instance = OpenAI(
        api_key=api_key,
        base_url=base_url
    )
    
    return _client_instance
