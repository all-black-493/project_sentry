import random
from circuit_breaker import call_agent

def dispatch_task(task_payload):
    # get snapshot of available agents
    agents=list(active_agents.keys())
    if not agents:
        return {"error":"No agents available; queued for later"}

    #shuffle to balance load
    random.shuffle(agents)

    for agent_id in agents:
        agent_url=f"http://{agent_id}:8001/execute"
        result=call_agent(agent_url, task_payload)
        if "error" not in result:
            return {"agent": agent_id, "result": result}
        #If circuit open or error, try next agent
    # All attempts failed; fallback: log and queue

    queue_fallback(task_payload)
    return {"error": "All agents busy or failing; task queued"}

def queue_fallback(payload):
    # For example, write to a redis list for entry
    import redis
    r = redis.Redis(host="localhost", port=6379, db=0)
    r.lpush("fallback_queue", payload)


if __name__=="__main__":
    task={"task": "prompt_fuzz", "data":"Test input"}
    print(dispatch_task(task))
