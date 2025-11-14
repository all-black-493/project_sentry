from pybreaker import CircuitBreaker, CircuitBreakerError
import requests
import os
from dotenv import load_dotenv

load_dotenv()

breaker = CircuitBreaker(fail_max=3, reset_timeout=60, name="AgentCircuit")


def call_agent(agent_url, payload):
    try:
        response = breaker.call(requests.post, agent_url, json=payload, timeout=5)
        return response.json()
    except CircuitBreakerError:
        return {"error": "Circuit open; skipping agent"}
    except Exception as exc:
        raise


if __name__ == "__main__":
    agent = os.getenv("AGENT_URL")
    result = call_agent(agent, {"task": "prompt_fuzz", "data": "Test"})
    print(result)
