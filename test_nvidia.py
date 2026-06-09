from dotenv import load_dotenv
from openai import OpenAI
import os

load_dotenv()

client = OpenAI(
    base_url=os.getenv("NVIDIA_API_BASE_URL"),
    api_key=os.getenv("NVIDIA_API_KEY")
)

response = client.chat.completions.create(
    model=os.getenv("YATA_LLM_MODEL"),
    messages=[
        {
            "role": "user",
            "content": "Reply with only the word SUCCESS"
        }
    ],
    max_tokens=10
)

print(response.choices[0].message.content)