"""jwt_fastapi app auth module."""
import uuid
from datetime import datetime
from datetime import timezone
from datetime import timedelta
from typing import Optional
from typing import NewType
from enum import StrEnum
from enum import auto

import jwt
from jwt.algorithms import get_default_algorithms
from jwt.algorithms import requires_cryptography
from jwt.algorithms import has_crypto

from jwt_fastapi.config import JWTConfig
from jwt_fastapi.config import TokenLocation
from jwt_fastapi.models import AccessTokenCreate
from jwt_fastapi.models import RefreshTokenCreate
from jwt_fastapi.models import TokenCreate
# from jwt_fastapi.models import ReservedClaims
from jwt_fastapi.models import TokenType
from jwt_fastapi.models import TypeAlias

Token = NewType("Token", str)


class EnDec(StrEnum):
    ENCODE = auto()
    DECODE = auto()

class JWTFastAPI:
    def __init__(self, config: JWTConfig) -> None:
        """JWTFastAPI class initializer."""
        self.config = config

    def create_access_token(self, payload: AccessTokenCreate) -> Token:
        """Create access token."""

        token_data = TokenCreate(**payload.model_dump(), alg=self.config.jf_algorithm)
        expire_time = payload.exp or self.config.jf_access_token_expire_duration
        if expire_time:
            seconds = int(expire_time.total_seconds())
            exp = int(datetime.now(timezone.utc).timestamp()) + seconds
            token_data.exp = exp

        return self._create_token(token_data)
        # return self._create_token(TokenCreate(**payload.model_dump(exclude_none=True)))

    def create_refresh_token(self, payload: RefreshTokenCreate) -> Token:
        """Create refresh token."""
        token_data = TokenCreate(**payload.model_dump(), alg=self.config.jf_algorithm)
        # token_data.alg = self.config.jf_algorithm
        expire_time = payload.exp or self.config.jf_refresh_token_expire_duration
        if expire_time:
            seconds = int(expire_time.total_seconds())
            exp = int(datetime.now(timezone.utc).timestamp()) + seconds
            token_data.exp = exp
        return self._create_token(token_data)
        # return self._create_token(TokenCreate(**payload.model_dump(exclude_none=True)))

    def _create_token(self, payload: TokenCreate) -> Token:
        """Create token."""
        token: str
        data: dict = dict()
        # data.update(**payload.model_dump(exclude_none=True))
        now = int(datetime.now(timezone.utc).timestamp())
        payload.nbf = payload.nbf or now
        payload.iat = payload.iat or now
        data.update(**payload.model_dump(exclude_none=True))

        # if payload.exp:
        #     data.update(exp=now + int(payload.exp.total_seconds()))

        # if reserved_claims.exp:
        #     update_exp = now + int(reserved_claims.exp.total_seconds())
        #     data.update(reserved_claims.model_dump(exclude_none=True), exp=update_exp)
        # else:
        #     data.update(reserved_claims.model_dump(exclude_none=True))

        custom_claims = dict()

        # if payload.token_type == TokenType.ACCESS:
        #     custom_claims['fresh'] = payload.fresh
        location_is_cookie = self.config.jf_token_location == TokenLocation.COOKIES
        if location_is_cookie and self.config.jf_csrf_protect_cookies:
            custom_claims["csrf"] = str(uuid.uuid4())

        # if payload.exp_time:
        #     reserved_claims.exp = payload.exp_time
        data.update(custom_claims)
        secret = self.get_secret_key(endec=EnDec.ENCODE)
        token = jwt.encode(data, secret, algorithm=payload.alg)
        return Token(token)

    def get_secret_key(self, endec: Optional[EnDec] = None) -> str:
        symmetric_algorithms: set = (
            set(get_default_algorithms()) - requires_cryptography
        )
        # asymmetric_algorithms:set = requires_cryptography
        alg = self.config.jf_algorithm
        if alg in symmetric_algorithms:
            if not self.config.jf_secret_key:
                raise RuntimeError(
                    "jf_secret_key must be set when using symetric algorithm"
                )
            return self.config.jf_secret_key
        elif alg in requires_cryptography:
            if endec is None:
                raise ValueError(
                        f"Argument `endec` can not be None when using asymmetric algorithm"
                        )
            match endec:
                case EnDec.ENCODE:
                    if not self.config.jf_private_key:
                        raise RuntimeError(
                    'jf_private_key must be set when using asymmetric algorithm `{alg}`'
                                )
                    return self.config.jf_private_key
                case EnDec.DECODE:
                    if not self.config.jf_public_key:
                        raise RuntimeError(
                    'jf_public_key must be set when using asymmetric algorithm `{alg}`'
                                )
                    return self.config.jf_public_key
                case _:
                    raise RuntimeError('Unknown token encode/decode operation value.')
        raise RuntimeError(f'Unsupported algorithm `{alg}`')


        # if algorithm in symmetric_algorithms:
        #     if not self._secret_key:
        #         raise RuntimeError(
        #             "authjwt_secret_key must be set when using symmetric algorithm {}".format(algorithm)
        #         )

        #     return self._secret_key

        # if algorithm in asymmetric_algorithms and not has_crypto:
        #     raise RuntimeError(
        #         "Missing dependencies for using asymmetric algorithms. run 'pip install fastapi-jwt-auth[asymmetric]'"
        #     )

        # if process == "encode":
        #     if not self._private_key:
        #         raise RuntimeError(
        #             "authjwt_private_key must be set when using asymmetric algorithm {}".format(algorithm)
        #         )

        #     return self._private_key

        # if process == "decode":
        #     if not self._public_key:
        #         raise RuntimeError(
        #             "authjwt_public_key must be set when using asymmetric algorithm {}".format(algorithm)
        #         )

        #     return self._public_key
