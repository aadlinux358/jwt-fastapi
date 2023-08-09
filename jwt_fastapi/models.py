"""Jwt_fastapi models module."""
from uuid import UUID
from datetime import timedelta
from datetime import datetime
from datetime import timezone
from enum import StrEnum, auto
from typing import Optional
from typing import Sequence
from typing import Final
from typing import TypeAlias

from pydantic import BaseModel, ConfigDict
from pydantic import StrictStr
from pydantic import field_validator

Subject: TypeAlias = str | int | UUID


class TokenType(StrEnum):
    ACCESS = auto()
    REFRESH = auto()


class TokenBase(BaseModel):
    """Token base model."""
    model_config = ConfigDict(
            from_attributes=True
            )

    sub: Subject
    aud: Optional[str | Sequence[str]] = None
    nbf: Optional[int] = None
    iat: Optional[int] = None
    headers: Optional[dict] = None
    user_claims: Optional[dict] = {}

    @field_validator("sub", mode="before")
    @classmethod
    def validate_subject(cls, v: Subject) -> str:
        return str(v)


class RefreshTokenCreate(TokenBase):
    token_type: TokenType = TokenType.REFRESH
    exp: Optional[timedelta] = None


class AccessTokenCreate(TokenBase):
    token_type: TokenType = TokenType.ACCESS
    exp: Optional[timedelta] = None
    fresh: Optional[bool] = False


class TokenCreate(TokenBase):
    """Token create model."""

    token_type: TokenType
    fresh: Optional[bool] = False
    alg: StrictStr
    exp: Optional[int] = None


# class ReservedClaims(BaseModel):
#     aud: Optional[str | list[str]] = None

#     @field_validator("sub", mode="before")
#     @classmethod
#     def validate_subject(cls, v: Subject) -> str:
#         return str(v)

    # @field_validator("exp", mode="before")
    # @classmethod
    # def change_timedelta_to_int(cls, v: int):
    #     if v is not None:
    #         t = datetime.now(timezone.utc)
    #         return int(t.timestamp()) + v
    #     return None
