from fastapi import APIRouter
from .prompt_fuzzer import router as prompt_fuzzer_router
from .metasploit_exploiter import router as metasploit_router

router = APIRouter()

router.include_router(prompt_fuzzer_router, prefix="/prompt-fuzzer")
router.include_router(metasploit_router, prefix="/metasploit")