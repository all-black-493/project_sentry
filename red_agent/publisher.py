import pika
import os
import time
from dotenv import load_dotenv

load_dotenv()

connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        host=os.getenv("RABBITMQ_HOST"),
        credentials=pika.PlainCredentials(
            "guest", "guest"
        ),
    )
)

channel = connection.channel()

exchange = "red_tasks_exchange"
dlx_exchange = "failed_tasks_exchange"
queue="red_tasks_queue"

channel.exchange_declare(exchange=exchange, exchange_type="direct", durable=True)
channel.exchange_declare(exchange=dlx_exchange, exchange_type="fanout", durable=True)

channel.queue_declare(
    queue=queue,
    durable=True,
    arguments={
        "x-dead-letter-exchange": dlx_exchange,
        "x-message-ttl": 60000 # 60 seconds TTL before dead-lettered
    }
)

channel.queue_bind(exchange=exchange, queue=queue, routing_key="prompt_fuzz")
channel.confirm_delivery()

message = "Run prompt fuzz against Model A"

if channel.basic_publish(
    exchange=exchange,
    routing_key="prompt_fuzz",
    body=message,
    properties=pika.BasicProperties(
        delivery_mode=2 #persistent
    )
):
    print("[x] Message delivered and acknowledged by RabbitMQ")
else:
    print("[!] Message could not be confirmed; handle failure")
    #e.g., Write to local file or retry

connection.close()
