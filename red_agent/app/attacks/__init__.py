from fastapi import APIRouter
from .prompt_fuzzer import router as prompt_fuzzer_router

router = APIRouter()

router.include_router(prompt_fuzzer_router, prefix="/prompt-fuzzer")