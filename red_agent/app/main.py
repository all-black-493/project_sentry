from fastapi import FastAPI
from app.attacks import router as attacks_router

# App initialization
app = FastAPI(
    title="Red Agent Service",
    description="API for launching adversarial attacks against target endpoints",
    version="1.0.0",
)

app.include_router(attacks_router, prefix="/attacks")


@app.get("/")
async def health_check():
    return {"status": "up"}
