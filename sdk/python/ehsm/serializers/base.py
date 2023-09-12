from typing import TypeVar, Generic
from httpx import Response
from pydantic.dataclasses import dataclass

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
        return EHSMResponse[cls](
            code=data["code"],
            message=data["message"],
            result=cls(**data["result"]),
        )
