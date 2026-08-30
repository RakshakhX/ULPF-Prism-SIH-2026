from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class ValidationIssue:
    path: str
    rule: str
    message: str


@dataclass(frozen=True)
class ValidationResult:
    issues: tuple[ValidationIssue, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.issues
