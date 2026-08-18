import json
import os
from typing import Any, Dict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from intelligent_security.domain import ModelProfile


class ModelGatewayError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def resolve_credential_reference(reference: str) -> str:
    """Resolve a configured secret reference without persisting its value.

    The POC supports only `env://VARIABLE_NAME`. Secret-manager adapters will be
    added later; callers must not put API keys in audit requests or JSON config.
    """
    prefix = "env://"
    if not reference.startswith(prefix):
        raise ModelGatewayError(
            "unsupported_credential_reference",
            "Only env:// credential references are supported by the POC model gateway.",
        )
    variable_name = reference[len(prefix) :]
    value = os.getenv(variable_name)
    if not value:
        raise ModelGatewayError(
            "credential_unavailable",
            "The configured model credential is not available in the environment.",
        )
    return value


class OpenAICompatibleModelGateway:
    """Minimal adapter for a configured OpenAI-compatible chat-completions API."""

    def generate_json(self, profile: ModelProfile, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        if profile.provider != "openai_compatible":
            raise ModelGatewayError(
                "unsupported_provider",
                "The POC supports the 'openai_compatible' provider only.",
            )
        api_key = resolve_credential_reference(profile.credential_reference)
        request_body = {
            "model": profile.model,
            "temperature": profile.temperature,
            "max_tokens": profile.max_output_tokens,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        request = Request(
            profile.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(request_body).encode("utf-8"),
            headers={
                "Authorization": "Bearer {}".format(api_key),
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=profile.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
            content = payload["choices"][0]["message"]["content"]
            return json.loads(content)
        except (HTTPError, URLError, TimeoutError, KeyError, IndexError, ValueError) as error:
            raise ModelGatewayError("model_request_failed", "Model request failed: {}".format(error))
