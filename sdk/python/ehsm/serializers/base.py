from typing import TypeVar, Generic
from httpx import Response
from pydantic.dataclasses import dataclass
from ehsm.exceptions import (
    InvalidParamException,
    ServerExceptionException,
    UnknownException,
)

T = TypeVar("T")
U = TypeVar("U")


@dataclass
class EHSMResponse(Generic[T]):
    code: int
    message: str
    result: T


class EHSMBase:
    @classmethod
    def from_response(cls, response: Response, *args, **kwargs):
        data = response.json()
        if "result" not in data:
            raise ValueError("Response does not have attribute 'result'")
        if data["code"] >= 400 and data["code"] < 500:
            raise InvalidParamException(
                f"Response has status {data['code']}: {data['message']}"
            )
        if data["code"] >= 500:
            raise ServerExceptionException(
                f"Response has status {data['code']}: {data['message']}"
            )
        if data["code"] != 200:
            raise UnknownException(
                f"Response has status {data['code']}: {data['message']}"
            )
        return EHSMResponse[cls](
            code=data["code"],
            message=data["message"],
            result=cls(**data["result"]),
        )
