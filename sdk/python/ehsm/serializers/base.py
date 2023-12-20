from typing import TypeVar
from httpx import Response
from pydantic import ConfigDict
from pydantic.dataclasses import dataclass
from ehsm.exceptions import (
    InvalidParamException,
    ServerExceptionException,
    UnknownException,
)

T = TypeVar("T")
U = TypeVar("U")


@dataclass
class EHSMResponse:
    code: int
    message: str


@dataclass(config=ConfigDict(arbitrary_types_allowed=True))
class EHSMBase:
    response: EHSMResponse
    raw_response: Response

    @classmethod
    def from_response(cls, response: Response, *args, **kwargs):
        data = response.json()
        if "result" not in data:
            raise ValueError("Response does not have attribute 'result'")
        if data["code"] >= 400 and data["code"] < 500:
            # `message` may possibly missing in the repsonse data
            message = f": {data['message']}" if "message" in data else ""
            raise InvalidParamException(f"Response has status {data['code']}" + message)
        if data["code"] >= 500:
            message = f": {data['message']}" if "message" in data else ""
            raise InvalidParamException(f"Response has status {data['code']}" + message)
        if data["code"] != 200:
            message = f": {data['message']}" if "message" in data else ""
            raise InvalidParamException(f"Response has status {data['code']}" + message)
        return cls(
            raw_response=response,
            response=EHSMResponse(code=data["code"], message=data["message"]),
            **data["result"],
        )
