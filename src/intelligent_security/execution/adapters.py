import json
import subprocess
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from intelligent_security.domain import Audit, ScheduledStep
from intelligent_security.execution.runtime_profiles import PluginRuntimeProfile
from intelligent_security.execution.result import AdapterExecutionResult
from intelligent_security.registry.service import PluginPackage


class ContainerCliAdapter:
    """Generic, constrained runner for admitted container-backed plugin packages."""

    def __init__(self, command_runner: Callable = subprocess.run) -> None:
        self.command_runner = command_runner

    def execute(
        self, runtime: PluginRuntimeProfile, audit: Audit, step: ScheduledStep, package: PluginPackage
    ) -> AdapterExecutionResult:
        if runtime.image_reference is None:
            raise RuntimeError("Container execution requires an approved image reference.")
        execution = package.execution
        if execution is None:
            raise RuntimeError("Plugin package has no approved execution specification.")
        target = self._authorized_target(audit, runtime, execution.target_input)
        command = [
            "docker", "run", "--rm", "--pull", "never", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "512m",
        ]
        command.extend(self._mount_arguments(package.root, execution.mounts))
        command.append(runtime.image_reference)
        command.extend(self._render_arguments(execution.arguments, target, execution.target_input))
        try:
            completed = self.command_runner(
                command, check=False, capture_output=True, text=True, timeout=runtime.max_runtime_seconds
            )
        except subprocess.TimeoutExpired as error:
            return AdapterExecutionResult(
                invocation=command,
                stdout=self._as_text(error.stdout),
                stderr=self._as_text(error.stderr),
                error_code="adapter_timeout",
                error_message="Container command exceeded its approved runtime limit.",
            )
        return AdapterExecutionResult(
            output_summary={
                "finding_count": self._count_output_records(completed.stdout, execution.output_format),
                "exit_code": completed.returncode,
                "output_format": execution.output_format,
            },
            invocation=command,
            stdout=completed.stdout,
            stderr=completed.stderr,
            exit_code=completed.returncode,
            error_code="adapter_nonzero_exit" if completed.returncode != 0 else None,
            error_message="Container command exited with code {}.".format(completed.returncode) if completed.returncode != 0 else None,
        )

    @staticmethod
    def _as_text(value) -> str:
        return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else (value or "")

    @staticmethod
    def _mount_arguments(package_root: Path, mounts: list) -> list:
        root = package_root.resolve()
        arguments = []
        for mount in mounts:
            source = (root / mount.source).resolve()
            if root not in source.parents and source != root or not source.exists():
                raise RuntimeError("Plugin execution mount is not available inside its package.")
            suffix = ":ro" if mount.read_only else ""
            arguments.extend(["-v", "{}:{}{}".format(source, mount.target, suffix)])
        return arguments

    @staticmethod
    def _render_arguments(arguments: list, target: str, target_input: str = "url") -> list:
        placeholder = "{{target.%s}}" % target_input
        rendered = []
        for argument in arguments:
            if "{{" in argument and argument != placeholder:
                raise RuntimeError("Plugin execution uses an unsupported argument placeholder.")
            rendered.append(target if argument == placeholder else argument)
        return rendered

    @staticmethod
    def _count_output_records(output: str, output_format: str) -> int:
        if output_format != "jsonl":
            return 0
        count = 0
        for line in output.splitlines():
            try:
                json.loads(line)
                count += 1
            except ValueError:
                continue
        return count

    @staticmethod
    def _authorized_target(audit: Audit, runtime: PluginRuntimeProfile, target_input: str = "url") -> str:
        if audit.target_profile is None or audit.scope_policy is None:
            raise RuntimeError("Validated target profile and scope policy are required.")
        target = audit.target_profile.canonical_identifier
        parsed = urlparse(target)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        allowed_hosts = {host.lower().rstrip(".") for host in runtime.allowed_target_hosts}
        if parsed.scheme != "https" or hostname not in audit.scope_policy.network_allowlist or hostname not in allowed_hosts:
            raise RuntimeError("Container target is not an authorized HTTPS runtime target.")
        return target if target_input == "url" else hostname
