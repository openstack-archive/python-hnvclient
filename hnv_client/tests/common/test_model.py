# Copyright 2017 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# pylint: disable=protected-access, missing-docstring

import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from hnv_client.common import exception
from hnv_client.common import model


class TestFieldDescriptor(unittest.TestCase):

    def test_field_access(self):
        instance = mock.Mock()
        field = mock.Mock()
        field_descriptor = model._FieldDescriptor(field)

        self.assertIs(field, field_descriptor.__get__(None))

        field_descriptor.__get__(instance)
        instance._data.get.assert_called_once_with(field.key)

    def test_set_field(self):
        instance = mock.MagicMock()
        instance._changes = {}

        field = mock.Mock()
        field.is_read_only = False
        field_descriptor = model._FieldDescriptor(field)
        field_descriptor.__set__(instance, mock.sentinel.value)

        self.assertIs(instance._changes[field.key], mock.sentinel.value)

    def test_set_read_only_field(self):
        instance = mock.MagicMock()

        field = mock.Mock()
        field.is_read_only = True
        field_descriptor = model._FieldDescriptor(field)
        with self.assertRaises(TypeError):
            field_descriptor.__set__(instance, mock.sentinel.value)

    def test_field_property(self):
        field = mock.Mock()
        field_descriptor = model._FieldDescriptor(field)

        self.assertIs(field_descriptor.field, field)


class TestField(unittest.TestCase):

    def test_properties(self):
        field = model.Field(name=mock.sentinel.name,
                            key=mock.sentinel.name,
                            default=mock.sentinel.default,
                            is_required=mock.sentinel.is_required,
                            is_property=mock.sentinel.is_property,
                            is_read_only=mock.sentinel.is_read_only)

        self.assertIs(field.name, mock.sentinel.name)
        self.assertIs(field.default, mock.sentinel.default)
        self.assertIs(field.is_required, mock.sentinel.is_required)
        self.assertIs(field.is_property, mock.sentinel.is_property)
        self.assertIs(field.is_read_only, mock.sentinel.is_read_only)

    @mock.patch("hnv_client.common.model._FieldDescriptor")
    def test_add_to_class(self, mock_field_descriptor):
        field = model.Field(name="test_add_to_class", key="test")
        model_class = mock.Mock()

        field.add_to_class(model_class)

        mock_field_descriptor.assert_called_once_with(field)
        self.assertIsNotNone(getattr(model_class, "test_add_to_class"))


class TestModelOptions(unittest.TestCase):

    def test_initialization(self):
        mock.sentinel.cls.__name__ = mock.sentinel.cls.name
        model_options = model._ModelOptions(cls=mock.sentinel.cls)

        self.assertIs(model_options._model_class, mock.sentinel.cls)
        self.assertEqual(model_options._name, mock.sentinel.cls.name)

    @mock.patch("six.callable")
    @mock.patch("hnv_client.common.model._ModelOptions.remove_field")
    def _test_add_field(self, mock_remove_field, mock_callable,
                        callable_default):
        model_options = model._ModelOptions(self.__class__)
        test_field = model.Field(name=mock.sentinel.name,
                                 key=mock.sentinel.key,
                                 is_required=False,
                                 default=mock.sentinel.default)
        mock_callable.return_value = callable_default

        model_options.add_field(test_field)

        mock_remove_field.assert_called_once_with(mock.sentinel.name)
        self.assertIs(model_options._fields[test_field.name], test_field)
        if callable_default:
            self.assertIs(model_options._default_callables[test_field.key],
                          mock.sentinel.default)
        else:
            self.assertIs(model_options._defaults[test_field.key],
                          mock.sentinel.default)

    def test_add_field(self):
        self._test_add_field(callable_default=False)
        self._test_add_field(callable_default=True)

    @mock.patch("six.callable")
    def _test_remove_field(self, mock_callable, callable_default):
        mock_callable.return_value = callable_default
        model_options = model._ModelOptions(self.__class__)
        test_field = model.Field(name=mock.sentinel.name,
                                 key="test_field",
                                 is_required=False,
                                 default=mock.sentinel.default)
        model_options.add_field(test_field)

        model_options.remove_field(test_field.name)

        self.assertNotIn(test_field.name, model_options._fields)
        if callable_default:
            self.assertNotIn(test_field.name,
                             model_options._default_callables)
        else:
            self.assertNotIn(test_field.name, model_options._defaults)

    def test_remove_field(self):
        self._test_remove_field(callable_default=False)
        self._test_remove_field(callable_default=True)

    def test_get_defaults(self):
        test_field = model.Field(
            name=mock.sentinel.name, key=mock.sentinel.key,
            is_required=False, default=lambda: mock.sentinel.default)
        model_options = model._ModelOptions(self.__class__)
        model_options.add_field(test_field)

        defaults = model_options.get_defaults()

        self.assertEqual(defaults, {mock.sentinel.key: mock.sentinel.default})


class TestBaseModel(unittest.TestCase):

    def test_create_model(self):

        class _Test(model.Model):
            field1 = model.Field(name="field1", key="field1", default=1)

        self.assertTrue(hasattr(_Test, "_meta"))
        self.assertEqual(_Test().field1, 1)

    def test_inherit_fields(self):

        class _TestBase(model.Model):
            field1 = model.Field(name="field1", key="key1",
                                 default=1)
            field2 = model.Field(name="field2", key="key2")

        class _Test(_TestBase):
            field2 = model.Field(name="field2", key="key2",
                                 default=2)

        class _FinalTest(_Test):
            field3 = model.Field(name="field3", key="key3",
                                 is_required=True)

        final_test = _FinalTest(field3=3)
        self.assertEqual(final_test.field1, 1)
        self.assertEqual(final_test.field2, 2)
        self.assertEqual(final_test.field3, 3)


class TestModel(unittest.TestCase):

    class _Test(model.Model):
        field1 = model.Field(name="field1", key="key1",
                             is_required=True,
                             is_property=False)
        field2 = model.Field(name="field2", key="key2",
                             is_required=False,
                             is_property=False)
        field3 = model.Field(name="field3", key="key3",
                             is_required=True,
                             is_property=True)

    def setUp(self):
        self._raw_data = {"key1": 1, "key2": 2, "properties": {"key3": 3}}

    def test_model_eq(self):
        test = self._Test(field1=1, field3=2)
        test2 = self._Test(field1=1, field3=3)
        self.assertFalse(test == self)
        self.assertTrue(test == test)
        self.assertFalse(test == test2)

    def test_validate(self):
        test = self._Test(field1=1, key="test_validate")
        self.assertRaises(exception.DataProcessingError, test.validate)

    def test_update(self):
        test = self._Test(field1="change_me", field2="change_me")
        test.update({"field1": mock.sentinel.field1,
                     "field2": mock.sentinel.field2})

        self.assertIs(test.field1, mock.sentinel.field1)
        self.assertIs(test.field2, mock.sentinel.field2)

    def test_dump(self):
        test = self._Test(field1=1, field2=2, field3=3)
        self.assertEqual(test.dump(), self._raw_data)

    def test_from_raw_data(self):
        test = self._Test.from_raw_data(self._raw_data)
        self.assertEqual(test.field1, 1)
        self.assertEqual(test.field2, 2)
        self.assertEqual(test.field3, 3)
