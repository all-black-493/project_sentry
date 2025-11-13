from kafka import KafkaProducer, KafkaAdminClient
from kafka.admin import NewTopic

import os
import json
import dotenv

dotenv.load_dotenv()

admin_client = KafkaAdminClient(
    bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS"), client_id="red-teaming-admin"
)

topic_name = "red_tasks_topic"
topic_list = [NewTopic(name=topic_name, num_partitions=3, replication_factor=1)]
existing_topics = admin_client.list_topics()

if topic_name not in existing_topics:
    admin_client.create_topics(new_topics=topic_list, validate_only=False)
    print(f"Created topic '{topic_name}'")

producer = KafkaProducer(
    bootstrap_servers=os.getenv("KAFKA_BOOTSTRAP_SERVERS"),
    key_serializer=lambda k: k.encode(),
    value_serializer=lambda v: json.dumps(v).encode(),
    acks="all",
)

key = "prompt_fuzz"
message = {"task": "run fuzz", "details": {"prompt": "Check X"}}    

future = producer.send(topic_name, key=key, value=message)
result = future.get(timeout=10)  # Block until message is sent
print(f"Sent message to partition {result.partition} with offset {result.offset}")

producer.flush()
producer.close()
