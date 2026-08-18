from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class AdapterExecutionResult:
    """Raw adapter result retained for evidence capture, plus a safe API summary."""

    output_summary: dict = field(default_factory=dict)
    invocation: List[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    artifacts: List[tuple] = field(default_factory=list)
