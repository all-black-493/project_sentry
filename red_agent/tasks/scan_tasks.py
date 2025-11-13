from celery import shared_task
from celery.exceptions import Retry

import requests


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def schedule_red_scan(self):
    """
    Publish multiple red-agent subtasks - for example, prompt fuzzing - via RabbitMQ.
    If the HTTP call to orchestrator fails, retry up to 3 times with 60 seconds delay .
    """

    try:
        # Example: send a request to orchestrator API to dispatch jobs
        response = requests.post(
            "http://localhost:8000/orchestrate/dispatch",
            json={"job_type": "prompt_fuzz", "params": {"template": "Test"}},
            timeout=10,
        )
        response.raise_for_status()
    except Exception as exc:
        raise self.retry(exc=exc)


@shared_task(bind=True)
def cleanup_failed_tasks(self):
    """
    Inspect RabbitMQ's failed_tasks queue and requeue or log as needed
    """

    # This could call a management API or use pika to consume from the DLQ
    # e.g., using pika, or leverage Celery events
    pass
