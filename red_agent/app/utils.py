import os
import httpx

from app.models.endpoint import TargetEndpoint


def load_env():
    from dotenv import load_dotenv
    load_dotenv()


async def post_payload(endpoint: TargetEndpoint, payload: str) -> httpx.Response:
    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {endpoint.api_key}"}
        response = await client.post(
            endpoint.url, json={"input": payload}, headers=headers
        )
        return response
