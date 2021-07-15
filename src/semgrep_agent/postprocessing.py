from copy import deepcopy
from fnmatch import fnmatch
from functools import partial
from pathlib import Path
from typing import Any
from typing import Callable
from typing import cast
from typing import Dict
from typing import List
from typing import Optional

from ruamel.yaml import YAML  # type: ignore

from semgrep_agent.findings import Finding

yaml = YAML(typ="rt")
CONFIG_PATH = Path.cwd() / ".semgrepconfig.yml"

OVERRIDE_CONDITIONS: Dict[str, Callable] = {}
OVERRIDE_ACTIONS: Dict[str, Callable] = {}


def register_function(
    function_mapping: Dict[str, Callable], override_key: str
) -> Callable[[Callable], Callable]:
    def wrapper(function: Callable) -> Callable:
        function_mapping[override_key] = function
        return function

    return wrapper


register_condition = partial(register_function, OVERRIDE_CONDITIONS)
register_action = partial(register_function, OVERRIDE_ACTIONS)


@register_condition("if.path")
def if_path(config_value: str, result: Dict[str, Any]) -> bool:
    return fnmatch(result.get("path", ""), config_value)


@register_condition("if.rule_id")
def if_rule_id(config_value: str, result: Dict[str, Any]) -> bool:
    return fnmatch(result.get("check_id", ""), config_value)


@register_condition("if.ruleset_id")
def if_ruleset_id(config_value: str, result: Dict[str, Any]) -> bool:
    return fnmatch(result.get("metadata", {}).get("semgrep.ruleset", ""), config_value)


@register_condition("if.policy_slug")
def if_policy_slug(config_value: str, result: Dict[str, Any]) -> bool:
    return fnmatch(
        result.get("metadata", {}).get("semgrep.policy", {}).get("slug", ""),
        config_value,
    )


@register_condition("if.severity_in")
def if_severity_in(config_value: List[str], result: Dict[str, Any]) -> bool:
    return result.get("extra", {}).get("severity", "") in config_value


@register_condition("if.finding_id")
def if_finding_id(config_value: str, result: Dict[str, Any]) -> bool:
    return (
        Finding.from_semgrep_result(result)
        .syntactic_identifier_str()
        .startswith(config_value)
    )


@register_action("mute")
def mute(config_value: bool, result: Dict[str, Any]) -> Dict[str, Any]:
    if not config_value:
        return result

    result.setdefault("extra", {})
    result["extra"]["is_ignored"] = True

    return result


@register_action("unmute")
def unmute(config_value: bool, result: Dict[str, Any]) -> Dict[str, Any]:
    if not config_value:
        return result

    result.setdefault("extra", {})
    result["extra"]["is_ignored"] = False

    return result


@register_action("set_severity")
def set_severity(config_value: str, result: Dict[str, Any]) -> Dict[str, Any]:
    result.setdefault("extra", {})
    result["extra"]["severity"] = config_value
    return result


def load_config() -> Optional[Dict[str, Any]]:
    if not CONFIG_PATH.exists():
        return None
    config = yaml.load(CONFIG_PATH.read_text())
    return cast(Dict[str, Any], config)


def update_result(result: Dict, overrides: List) -> Dict[str, Any]:
    for override in overrides:
        if all(
            OVERRIDE_CONDITIONS[override_key](override_value, result)
            for override_key, override_value in override.items()
            if override_key in OVERRIDE_CONDITIONS
        ):
            for override_key, override_value in override.items():
                if override_key in OVERRIDE_ACTIONS:
                    result = OVERRIDE_ACTIONS[override_key](override_value, result)

    return result


def postprocess(results: List) -> List:
    config = load_config()
    if not config:
        return results

    new_results = deepcopy(results)

    for result in new_results:
        result = update_result(result, config["overrides"])

    return new_results
