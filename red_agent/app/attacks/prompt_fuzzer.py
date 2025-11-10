from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class FuzzRequest(BaseModel):
    prompt_template: str
    mutation_strategy: str


class FuzzResponse(BaseModel):
    fuzzed_prompt: str
    success: bool
    details: dict


@router.post("/fuzz", response_model=FuzzResponse)
async def fuzz_prompt(request: FuzzRequest):
    # Placeholder: Replace with real fuzzing logic using an LLM
    if not request.prompt_template:
        raise HTTPException(status_code=400, detail="Prompt template required")
    # Simple mutation example - append a directive
    fuzzed = f"{request.prompt_template} -- Injected: {request.mutation_strategy}"

    return FuzzResponse(
        fuzzed_prompt=fuzzed,
        success=True,
        details={"strategy": request.mutation_strategy},
    )
