from typing import Any
from typing import Dict
from typing import IO
from typing import Union

import yaml as pyyaml


class YamlSerializer:
    """Custom YAML serializer set up for human-readable formatting."""

    def dump(self, data: Any) -> str:
        result: str = pyyaml.dump(
            data, Dumper=pyyaml.CSafeDumper, default_flow_style=False, sort_keys=False
        )
        if result is None:  # make mypy happy
            raise RuntimeError("PyYAML's dump() returned None")
        return result

    def load(self, stream: Union[bytes, str, IO[bytes], IO[str]]) -> Any:
        return pyyaml.load(stream, Loader=pyyaml.CSafeLoader)

    safe_dump = dump
    safe_load = load


yaml = YamlSerializer()
