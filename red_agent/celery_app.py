from celery import Celery
from celery.schedules import crontab

app = Celery(
    "red_team_orchestrator",
    broker="amqp://guest:guest@localhost:5672//",
    backend="redis://localhost:6379/0",
)

app.autodiscover_tasks(["tasks.scan_tasks"])

# Configure beat schedule for periodic tasks

app.conf.beat_schedule = {
    # Example: run 'schedule_red_scan' every day at midnight
    "daily-red-scan": {
        "task":"tasks.scan_tasks.schedule_red_scan",
        "schedule": crontab(hour=0, minute=0),
        "args":(),
    },

    #Example run 'cleanup_failed_tasks' every hour

    "hourly-cleanup": {
        "task":"tasks.scan_tasks.cleanup_failed_tasks",
        "schedule": crontab(minute=0, hour="*")
    }
}

app.conf.task_serializer = "json"
app.conf.result_serializer = "json"
app.conf.accept_content = ["json"]
app.conf.broker_transport_options = {"visibility_timeout": 3600}
