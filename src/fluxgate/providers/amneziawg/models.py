"""Typed, persistent AmneziaWG 3.1 resilience profiles."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from fluxgate.core.compat import StrEnum
from fluxgate.core.models import StrictModel


class ResiliencePreset(StrEnum):
    STANDARD = "standard"
    BALANCED = "balanced"
    ENHANCED = "enhanced"


class AmneziaWGParameters(StrictModel):
    """Conservative AWG 3.1 subset unaffected by known advanced-feature defects."""

    jc: int = Field(ge=1, le=128)
    jmin: int = Field(ge=0, lt=1280)
    jmax: int = Field(gt=0, le=1280)
    s1: int = Field(ge=0, le=1132)
    s2: int = Field(ge=0, le=1188)
    h1: int = Field(ge=5, le=2_147_483_647)
    h2: int = Field(ge=5, le=2_147_483_647)
    h3: int = Field(ge=5, le=2_147_483_647)
    h4: int = Field(ge=5, le=2_147_483_647)

    @model_validator(mode="after")
    def compatible_values(self) -> AmneziaWGParameters:
        if self.jmin >= self.jmax:
            raise ValueError("AmneziaWG Jmin must be less than Jmax")
        if self.s1 + 56 == self.s2:
            raise ValueError("AmneziaWG S1 + 56 must not equal S2")
        headers = (self.h1, self.h2, self.h3, self.h4)
        if len(set(headers)) != 4:
            raise ValueError("AmneziaWG H1, H2, H3 and H4 must be unique")
        return self


PRESET_PARAMETERS: dict[ResiliencePreset, AmneziaWGParameters] = {
    ResiliencePreset.STANDARD: AmneziaWGParameters(
        jc=4, jmin=40, jmax=80, s1=64, s2=96, h1=1001, h2=1002, h3=1003, h4=1004
    ),
    ResiliencePreset.BALANCED: AmneziaWGParameters(
        jc=6, jmin=48, jmax=104, s1=72, s2=112, h1=2001, h2=2002, h3=2003, h4=2004
    ),
    ResiliencePreset.ENHANCED: AmneziaWGParameters(
        jc=8, jmin=64, jmax=128, s1=80, s2=128, h1=3001, h2=3002, h3=3003, h4=3004
    ),
}


class ResilienceProfile(StrictModel):
    schema_version: Literal[1] = 1
    id: UUID = Field(default_factory=uuid4)
    name: str
    provider: Literal["amneziawg"] = "amneziawg"
    generation: Literal["awg-3.1"] = "awg-3.1"
    preset_origin: ResiliencePreset
    parameters: AmneziaWGParameters
    enabled: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        if (
            not (1 <= len(value) <= 64)
            or not value[0].isalnum()
            or any(not (character.isalnum() or character in {"-", "_", "."}) for character in value)
            or value in {".", ".."}
        ):
            raise ValueError(
                "resilience profile name may contain letters, digits, '.', '_' and '-'"
            )
        return value

    @classmethod
    def from_preset(cls, name: str, preset: ResiliencePreset) -> ResilienceProfile:
        return cls(
            name=name,
            preset_origin=preset,
            parameters=PRESET_PARAMETERS[preset].model_copy(deep=True),
        )


class AmneziaWGProviderState(StrictModel):
    schema_version: Literal[1] = 1
    enabled: bool = False
    backend: Literal["userspace"] = "userspace"
    profile: ResilienceProfile
