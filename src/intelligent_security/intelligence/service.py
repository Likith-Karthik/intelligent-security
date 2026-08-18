import hashlib
import json

from intelligent_security.planning.model_gateway import OpenAICompatibleModelGateway
from intelligent_security.planning.model_profiles import ModelProfileRegistry


class IntelligenceService:
    """Select a purpose-specific model profile and retain call provenance."""

    def __init__(self, profiles: ModelProfileRegistry, gateway: OpenAICompatibleModelGateway = None) -> None:
        self.profiles = profiles
        self.gateway = gateway or OpenAICompatibleModelGateway()

    def generate(self, purpose: str, system_prompt: str, context: dict) -> tuple:
        profile = self.profiles.select_profile(purpose)
        payload = json.dumps(context, sort_keys=True, separators=(",", ":"))
        result = self.gateway.generate_json(profile, system_prompt, payload)
        return result, {
            "purpose": purpose,
            "model_profile_id": profile.profile_id,
            "input_digest": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "output_digest": hashlib.sha256(json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest(),
        }
