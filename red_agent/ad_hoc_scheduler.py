from apscheduler.schedulers.blocking import BlockingScheduler
from celery_app import app

scheduler = BlockingScheduler()

def enqueue_fuzz_job():
    app.send_task("tasks.schedule_red_scan")
    print("[->] Enqueued immediate red-scan task")

scheduler.add_job(enqueue_fuzz_job, trigger="date", run_date="2025-11-14 12:00:00")

if __name__=="__main__":
    print("[*] APScheduler running; will enqueue tasks at specific times")
    scheduler.start()