from typing import List
from unittest import TestCase
from dataclasses import dataclass
from httpx import Response

from .base import (
    EHSMBase,
    EHSMResponse
)


# define simple dataclass for tests
@dataclass
class Item:
    x: int
    y: int

@dataclass
class ItemWithBase(EHSMBase):
    x: int
    y: int

@dataclass
class ItemList(EHSMBase):
    items: List[Item]


class TestEHSMBase(TestCase):

    def test_serialize_dataclass(self):
        # construct raw object
        raw = dict(x=1, y=2)
        item = ItemWithBase.from_dict(raw)
        self.assertEqual(item.x, 1)
        self.assertEqual(item.y, 2)
        
    def test_serialize_nested_dataclass(self):
        # construct raw object
        raw = dict(
            items=[dict(x=1, y=2), dict(x=10, y=20)]
        )
        items_list = ItemList.from_dict(raw)
        # check ItemList type
        self.assertTrue(isinstance(items_list, ItemList))
        # check items
        self.assertTrue(isinstance(items_list.items, list))
        self.assertTrue(len(items_list.items), 2)
        self.assertTrue(all([isinstance(item, Item) for item in items_list.items]))

    def test_serialize_from_response(self):
        raw_result = dict(
            code=200,
            message='Success',
            result=dict(items=[dict(x=1, y=2), dict(x=10, y=3)])
        )
        raw_response = Response(status_code=200, json=raw_result)
        response = ItemList.from_response(raw_response)
        # check code and message
        self.assertEqual(response.code, raw_result['code'])
        self.assertEqual(response.message, raw_result['message'])
        # check items_list
        items_list = response.result
        # check ItemList type
        self.assertTrue(isinstance(items_list, ItemList))
        # check items
        self.assertTrue(isinstance(items_list.items, list))
        self.assertTrue(len(items_list.items), 2)
        self.assertTrue(all([isinstance(item, Item) for item in items_list.items]))
