import json
from pathlib import Path
from typing import List, Optional

from intelligent_security.domain import ModelProfile


class ModelProfileError(Exception):
    pass


class ModelProfileRegistry:
    def __init__(self, config_path: Optional[str] = None) -> None:
        default_path = Path(__file__).resolve().parents[3] / "config" / "model_profiles.json"
        self.config_path = Path(config_path) if config_path else default_path

    def load_profiles(self) -> List[ModelProfile]:
        if not self.config_path.exists():
            return []
        try:
            with self.config_path.open(encoding="utf-8") as config_file:
                content = json.load(config_file)
            profiles = [ModelProfile.model_validate(item) for item in content.get("profiles", [])]
        except (OSError, ValueError, TypeError) as error:
            raise ModelProfileError("Unable to load model profiles: {}".format(error))
        profile_ids = [profile.profile_id for profile in profiles]
        if len(profile_ids) != len(set(profile_ids)):
            raise ModelProfileError("Model profile IDs must be unique.")
        return profiles

    def select_planner_profile(self, profile_id: Optional[str]) -> ModelProfile:
        return self.select_profile("audit_planning", profile_id)

    def select_profile(self, purpose: str, profile_id: Optional[str] = None) -> ModelProfile:
        profiles = [
            profile
            for profile in self.load_profiles()
            if profile.enabled and profile.purpose == purpose
        ]
        if profile_id:
            for profile in profiles:
                if profile.profile_id == profile_id:
                    return profile
            raise ModelProfileError("No enabled {} profile named '{}' exists.".format(purpose, profile_id))
        defaults = [profile for profile in profiles if profile.default_for_purpose]
        if len(defaults) == 1:
            return defaults[0]
        if not profiles:
            # A single planning profile is sufficient for the POC; production should
            # configure separate profiles for every intelligence purpose.
            profiles = [profile for profile in self.load_profiles() if profile.enabled and profile.purpose == "audit_planning"]
        defaults = [profile for profile in profiles if profile.default_for_purpose]
        if len(defaults) == 1:
            return defaults[0]
        if not profiles:
            raise ModelProfileError("No enabled {} model profile is configured.".format(purpose))
        raise ModelProfileError("Select one {} model profile; no unique default is configured.".format(purpose))
