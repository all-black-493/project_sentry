import pika
import os
import time
from dotenv import load_dotenv

load_dotenv()

connection = pika.BlockingConnection(
    pika.ConnectionParameters(
        host=os.getenv("RABBITMQ_HOST"),
        credentials=pika.PlainCredentials("guest", "guest"),
    )
)

channel = connection.channel()

exchange = "red_tasks_exchange"
dlx_exchange = "failed_tasks_exchange"
queue = "red_tasks_queue"
failed_queue = "failed_tasks_queue"

channel.exchange_declare(exchange=exchange, exchange_type="direct", durable=True)
channel.exchange_declare(exchange=dlx_exchange, exchange_type="fanout", durable=True)

channel.queue_declare(
    queue=queue,
    durable=True,
    arguments={
        "x-dead-letter-exchange": dlx_exchange,
        "x-message-ttl": 60000,  # 60 seconds TTL before dead-lettered
    },
)

channel.queue_bind(exchange=exchange, queue=queue, routing_key="prompt_fuzz")

channel.queue_declare(queue=failed_queue, durable=True)
channel.queue_bind(exchange=dlx_exchange, queue=failed_queue)

def callback(ch, method, properties, body):
    task = body.decode()
    print(f"[x] Received task: {task}")

    try:
        # Insert red-agent task execution here
        success=True # or False based on execution result
        if success:
            ch.basic_ack(delivery_tag=method.delivery_tag)
            print("[✓] Task completed and acknowledged")
        else:
            headers=properties.headers or{}
            retries=headers.get("x-retries",0)+1
            if retries<3:
                # Republish with incremented retry count and short delay
                ch.basic_publish(
                    exchange=exchange,
                    routing_key="prompt_fuzz",
                    body=task,
                    properties=pika.BasicProperties(
                        headers={"x-retries": retries},
                        delivery_mode=2
                    )
                )
                ch.basic_ack(
                    delivery_tag=method.delivery_tag
                )
                print(f"[->] Requeued task (retry {retries})")

            else: 
                # Reject without requeue - moves to DLX
                ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
                print("[x] Task failed; sent to dead-letter queue")

    except Exception as exc:
        # On unexpected error, reject without requeue so it lands in DLX
        ch.basic_nack(delivery_tag=method.delivery_tag, requeue=False)
        print(f"[!] Exception during task: {exc}; moved to DLQ")

channel.basic_qos(prefetch_count=1)
channel.basic_consume(queue=queue, on_message_callback=callback)

print("[*] Waiting for tasks. To exit press CTRL+C")
channel.start_consuming()

