from dataclasses import dataclass, fields, is_dataclass, Field
from typing import TypeVar, Generic, Dict, get_type_hints
from copy import deepcopy
from httpx import Response

T = TypeVar("T")
U = TypeVar("U")


def has_list_notation(field: Field):
    origin = getattr(field.type, '__origin__', None)
    return origin and issubclass(origin, list)


def extract_list_notation_generic(field: Field):
    """
    Suppose `field` is a a `typing.List[S]` while S is any type,
    this function returns `S` (return instance of `TypeVar` if S is not 
    declared in type annotation)

    Returns `None` when `field` has no __origin__ or __args__ attribute
    """
    if not has_list_notation(field):
        return None
    args = getattr(field.type, '__args__', None)
    if not args or len(args) == 0:
        return None
    return args[0]


@dataclass
class EHSMResponse(Generic[T]):
    code: int
    message: str
    result: T


class EHSMBase:
    @classmethod
    def from_dict(cls, raw_dict: Dict):
        """
        Construct a dataclass from a dict
        """
        # _cls a shadow copy of `cls` for typing. The `is_dataclass(cls)` 
        # method will change the type of cls to Type[DataInstance], which will
        # change the return value of this function to Type[DataInstance]
        # instead of `cls` type.
        _cls = cls
        if not is_dataclass(_cls):
            raise ValueError("EHSMBase.from_dict must be used as base of a dataclass")
        init_params = deepcopy(raw_dict)
        # recursivly init objects with `from_dict` function in order to support
        # loading nested dataclass from dict
        for field in fields(_cls):  # pragma nocover
            if field.name not in init_params.keys():
                continue
            # deal with field which type is a dataclass
            if is_dataclass(field.type):
                init_params[field.name] = cls._parse_dataclass_field_from_dict(
                    field_type=field.type,
                    raw_dict=init_params[field.name],
                )
            # deal with field which type is typing.List
            field_type = extract_list_notation_generic(field)
            # ignore if _field_type is not a dataclass
            if field_type and is_dataclass(field_type):
                instances = []
                for item in init_params[field.name]:
                    instances.append(cls._parse_dataclass_field_from_dict(
                        field_type=field_type,
                        raw_dict=item
                    ))
                init_params[field.name] = instances
        return cls(**init_params)

    @classmethod
    def _parse_dataclass_field_from_dict(cls, field_type: type, raw_dict: Dict):
        """
        Parse a dataclass typed field from given dict
        """
        if not is_dataclass(field_type):
            raise ValueError("field_type must be a subclass of dataclass")
        if issubclass(field_type, EHSMBase):
            return field_type.from_dict(raw_dict)
        else:
            return field_type(**raw_dict)

    @classmethod
    def from_response(cls, response: Response, *args, **kwargs):
        data = response.json()
        if "result" not in data:
            raise ValueError("Response does not have attribute 'result'")
        return EHSMResponse[cls](
            code=data["code"],
            message=data["message"],
            result=cls.from_dict(data["result"]),
        )
