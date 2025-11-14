import random

from deepteam.attacks.single_turn import BaseSingleTurnAttack
from deepteam.attacks.single_turn.prompt_injection.template import (
    PromptInjectionTemplate,
)


class PromptInjection(BaseSingleTurnAttack):
    def __init__(self, weight: int = 1):
        self.weight = weight

    def enhance(self, attack: str) -> str:
        return random.choice(
            [
                PromptInjectionTemplate.enhance_1(attack),
                PromptInjectionTemplate.enhance_2(attack),
            ]
        )

    async def a_enhance(self, attack: str) -> str:
        return self.enhance(attack)

    def get_name(self) -> str:
        return "Prompt Injection"
