from dataclasses import dataclass
from typing import List, Dict, Union


@dataclass
class ContentProviderApi:
    uri: str

    def __eq__(self, other):
        if isinstance(other, ContentProviderApi):
            return self.uri == other.uri
        return NotImplemented


@dataclass
class StaticAnalysisResult:
    class_name: str
    fuzzing_requests: List[ContentProviderApi]


@dataclass
class ApiFuzzingResult:
    input: ContentProviderApi
    permission_names: List[str]

    thrown_exception: str
    stacktrace: str

    def __eq__(self, other):
        if isinstance(other, ApiFuzzingResult):
            return self.input == other.input
        return NotImplemented


@dataclass
class CallApi(ContentProviderApi):
    api_level: str
    method: str
    arg: Union[str, None]
    extras: Union[str, None]

    def __eq__(self, other):
        if isinstance(other, CallApi):
            return super().__eq__(other) and \
                   self.api_level == other.api_level and \
                   self.method == self.method and \
                   self.arg == other.arg and \
                   self.extras == other.extras
        return NotImplemented


@dataclass
class DeleteApi(ContentProviderApi):
    selection: Union[str, None]

    def __eq__(self, other):
        if isinstance(other, DeleteApi):
            return super().__eq__(other) and \
                   self.selection == other.selection
        return NotImplemented


@dataclass
class InsertApi(ContentProviderApi):
    content_values: Dict

    def __eq__(self, other):
        if isinstance(other, InsertApi):
            return super().__eq__(other) and \
                   self.content_values == other.content_values
        return NotImplemented


@dataclass
class QueryApi(ContentProviderApi):
    projection: Union[str, None]
    selection: Union[str, None]
    selection_args: Union[str, None]
    sort_order: Union[str, None]

    def __eq__(self, other):
        if isinstance(other, QueryApi):
            return super().__eq__(other) and \
                   self.projection == other.projection and \
                   self.selection == self.selection and \
                   self.selection_args == other.selection_args and \
                   self.sort_order == other.sort_order
        return NotImplemented


@dataclass
class UpdateApi(ContentProviderApi):
    content_values: Dict
    selection: Union[str, None]

    def __eq__(self, other):
        if isinstance(other, UpdateApi):
            return super().__eq__(other) and \
                   self.content_values == other.content_values and \
                   self.selection == self.selection
        return NotImplemented
