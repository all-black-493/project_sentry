import asyncio
import json
import os
import pika
import time

from dotenv import load_dotenv

load_dotenv()

rabbit_url=os.getenv("RABBITMQ_URL")
active_agents={} #agent_id -> last_timestamp


def heartbeat_callback(ch, method, properties, body):
    data = json.loads(body)
    active_agents[data["agent_id"]]=data["timestamp"]

async def cleanup_inactive_agents():
    while True:
        now = time.time()
        for agent_id, ts in list(active_agents.items()):
            if now - ts > 30:
                del active_agents[agent_id]
            await asyncio.sleep(5)

async def main():
    params = pika.URLParameters(rabbit_url)
    connection=pika.BlockingConnection(params)
    channel=connection.channel()
    channel.exchange_declare(exchange="agent_heartbeats", exchange_type="fanout", durable=True)
    result=channel.queue_declare(queue="", exclusive=True)
    queue_name=result.method.queue
    channel.queue_bind(exchange="agent_heartbeats", queue=queue_name)
    channel.basic_consume(queue=queue_name, on_message_callback=heartbeat_callback, auto_ack=True)
    asyncio.create_task(cleanup_inactive_agents())
    print("[*] Orchestrator listening for heartbeats")
    channel.start_consuming()

if __name__=="__main__":
    asyncio.run(main())