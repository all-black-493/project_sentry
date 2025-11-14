# red_teaming_example.py
import os
import asyncio
import logging
from openai import AsyncOpenAI
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("gemini_red_team")


load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    logger.error("GEMINI_API_KEY is missing in .env!")
    raise ValueError("GEMINI_API_KEY not found")

logger.info(f"Loaded GEMINI_API_KEY: {api_key[:6]}... (truncated)")

client = AsyncOpenAI(
    api_key=api_key,
    base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
)
async def model_callback(input_text: str) -> str:
    logger.info(f"Sending request → {input_text[:80]}...")

    try:
        response = await client.chat.completions.create(
            model="gemini-2.0-flash",
            messages=[
                {"role": "user", "content": input_text}
            ],
        )

        output = response.choices[0].message.content
        logger.info(f"Received response ← {output[:120]}...")

        return output

    except Exception as e:
        logger.exception("Gemini API call failed!")
        raise e


# Manual test
if __name__ == "__main__":
    async def _test():
        result = await model_callback("Hello! Test logging.")
        print("\nMODEL OUTPUT:", result)

    asyncio.run(_test())