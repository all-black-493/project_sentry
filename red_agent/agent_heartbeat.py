import asyncio
import json
import os
import pika
import time
import uuid

from dotenv import load_dotenv

load_dotenv()


rabbit_url = os.getenv("RABBITMQ_URL")
agent_id = str(uuid.uuid4())


async def send_heartbeat():
    params = pika.URLParameters(rabbit_url)
    connection = pika.BlockingConnection(params)
    channel = connection.channel()
    channel.exchange_declare(
        exchange="agent_heartbeats", exchange_type="fanout", durable=True
    )

    while True:
        heartbeat = {"agent_id": agent_id, "timestamp": time.time()}
        channel.basic_publish(
            exchange="agent_heartbeats",
            routing_key="",
            body=json.dumps(heartbeat),
            properties=pika.BasicProperties(delivery_mode=1),
        )
        await asyncio.sleep(10)


if __name__ == "__main__":
    asyncio.run(send_heartbeat())
