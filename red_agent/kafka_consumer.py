from kafka import KafkaConsumer
import os
import dotenv
import json

dotenv.load_dotenv()

topic_name="red_tasks_topic"

consumer = KafkaConsumer(
    topic_name,
    bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS"),
    group_id="red_agent_group",
    value_deserializer=lambda v: json.loads(v.decode()),
    auto_offset_reset="earliest",
    enable_auto_commit=False
)

print(f"Subscribed to topic '{topic_name}'. Waiting for messages ...")
for message in consumer:
    key=message.key.decode() if message.key else None
    payload=message.value
    print(f"Received message: key = {key}, payload={payload}")

    # Very important: Insert attack execution logic here
    consumer.commit()