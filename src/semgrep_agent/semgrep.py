import io
import json
import os
import sys
import time
import urllib.parse
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from textwrap import dedent
from textwrap import indent
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import TextIO
from typing import TYPE_CHECKING
from typing import Union

import attr
import click
import requests
import sh
from boltons.iterutils import chunked_iter
from boltons.strutils import unit_len
from sh.contrib import git

from semgrep_agent.findings import Finding
from semgrep_agent.findings import FindingSets
from semgrep_agent.targets import TargetFileManager
from semgrep_agent.utils import debug_echo

if TYPE_CHECKING:
    from semgrep_agent.semgrep_app import Scan

ua_environ = {"SEMGREP_USER_AGENT_APPEND": "(Agent)", **os.environ}
semgrep = sh.semgrep.bake(_ok_code={0, 1}, _tty_out=False, _env=ua_environ)

# a typical old system has 128 * 1024 as their max command length
# we assume an average ~250 characters for a path in the worst case
PATHS_CHUNK_SIZE = 500


def resolve_config_shorthand(config: str) -> str:
    maybe_prefix = config[:2]
    if maybe_prefix in {"p/", "r/"}:
        return f"https://semgrep.dev/c/{config}"
    elif maybe_prefix == "s/":
        return f"https://semgrep.dev/c/{config[2:]}"
    else:
        return config


def get_semgrepignore(ignore_patterns: List[str]) -> TextIO:
    semgrepignore = io.StringIO()
    TEMPLATES_DIR = (Path(__file__).parent / "templates").resolve()

    semgrepignore_path = Path(".semgrepignore")
    if semgrepignore_path.is_file():
        click.echo("| using path ignore rules from .semgrepignore", err=True)
        semgrepignore.write(semgrepignore_path.read_text())
    else:
        click.echo(
            "| using default path ignore rules of common test and dependency directories",
            err=True,
        )
        semgrepignore.write((TEMPLATES_DIR / ".semgrepignore").read_text())

    if ignore_patterns:
        click.echo(
            "| adding further path ignore rules configured on the web UI", err=True
        )
        semgrepignore.write("\n# Ignores from semgrep app\n")
        semgrepignore.write("\n".join(ignore_patterns))
        semgrepignore.write("\n")

    return semgrepignore


@dataclass
class Results:
    findings: FindingSets
    total_time: float

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "findings": len(self.findings.new),
            "total_time": self.total_time,
        }


def rewrite_sarif_file(sarif_path: Path) -> None:
    """Fix SARIF errors in semgrep output and pretty format the file."""

    with sarif_path.open() as sarif_file:
        sarif_results = json.load(sarif_file)

    rules_by_id = {
        rule["id"]: rule for rule in sarif_results["runs"][0]["tool"]["driver"]["rules"]
    }
    sarif_results["runs"][0]["tool"]["driver"]["rules"] = list(rules_by_id.values())

    with sarif_path.open("w") as sarif_file:
        json.dump(sarif_results, sarif_file, indent=2, sort_keys=True)


def invoke_semgrep(
    config_specifier: str,
    committed_datetime: Optional[datetime],
    base_commit_ref: Optional[str],
    semgrep_ignore: TextIO,
    uses_managed_policy: bool,
) -> FindingSets:
    debug_echo("=== adding semgrep configuration")

    workdir = Path.cwd()
    targets = TargetFileManager(
        base_path=workdir,
        base_commit=base_commit_ref,
        paths=[workdir],
        ignore_rules_file=semgrep_ignore,
    )

    config_args = ["--config", config_specifier]
    rewrite_args = ["--no-rewrite-rule-ids"] if uses_managed_policy else []

    debug_echo("=== seeing if there are any findings")
    findings = FindingSets()

    with targets.current_paths() as paths:
        click.echo(
            "=== looking for current issues in " + unit_len(paths, "file"), err=True
        )
        for chunk in chunked_iter(paths, PATHS_CHUNK_SIZE):
            args = [
                "--skip-unknown-extensions",
                "--disable-nosem",
                "--json",
                *rewrite_args,
                *config_args,
            ]
            for path in chunk:
                args.append(path)
            semgrep_results = json.loads(str(semgrep(*args)))["results"]
            findings.current.update_findings(
                Finding.from_semgrep_result(result, committed_datetime)
                for result in semgrep_results
                if not result["extra"].get("is_ignored")
            )
            findings.ignored.update_findings(
                Finding.from_semgrep_result(result, committed_datetime)
                for result in semgrep_results
                if result["extra"].get("is_ignored")
            )
            click.echo(
                f"| {unit_len(findings.current, 'current issue')} found", err=True
            )
            click.echo(
                f"| {unit_len(findings.ignored, 'ignored issue')} found",
                err=True,
            )

    if not findings.current:
        click.echo(
            "=== not looking at pre-existing issues since there are no current issues",
            err=True,
        )
    else:
        with targets.baseline_paths() as paths:
            paths_with_findings = {finding.path for finding in findings.current}
            paths_to_check = set(str(path) for path in paths) & paths_with_findings
            if not paths_to_check:
                click.echo(
                    "=== not looking at pre-existing issues since all files with current issues are newly created",
                    err=True,
                )
            else:
                click.echo(
                    "=== looking for pre-existing issues in "
                    + unit_len(paths_to_check, "file"),
                    err=True,
                )
                for chunk in chunked_iter(paths_to_check, PATHS_CHUNK_SIZE):
                    args = [
                        "--skip-unknown-extensions",
                        "--json",
                        *rewrite_args,
                        *config_args,
                    ]
                    for path in chunk:
                        args.append(path)
                    semgrep_results = json.loads(str(semgrep(*args)))["results"]
                    findings.baseline.update_findings(
                        Finding.from_semgrep_result(result, committed_datetime)
                        for result in semgrep_results
                    )
                click.echo(
                    f"| {unit_len(findings.baseline, 'pre-existing issue')} found",
                    err=True,
                )

    if os.getenv("INPUT_GENERATESARIF"):
        # FIXME: This will crash when running on thousands of files due to command length limit
        click.echo("=== re-running scan to generate a SARIF report", err=True)
        sarif_path = Path("semgrep.sarif")
        with targets.current_paths() as paths, sarif_path.open("w") as sarif_file:
            args = ["--sarif", *rewrite_args, *config_args]
            for path in paths:
                args.extend(["--include", path])
            semgrep(*args, _out=sarif_file)
        rewrite_sarif_file(sarif_path)

    return findings


def scan(
    config_specifier: str,
    committed_datetime: Optional[datetime],
    base_commit_ref: Optional[str],
    semgrep_ignore: TextIO,
    uses_managed_policy: bool,
) -> Results:
    before = time.time()
    try:
        findings = invoke_semgrep(
            config_specifier,
            committed_datetime,
            base_commit_ref,
            semgrep_ignore,
            uses_managed_policy,
        )
    except sh.ErrorReturnCode as error:
        message = f"""
        === failed command's STDOUT:

{indent(error.stdout.decode(), 8 * ' ')}

        === failed command's STDERR:

{indent(error.stderr.decode(), 8 * ' ')}

        === [ERROR] `{error.full_cmd}` failed with exit code {error.exit_code}

        This is an internal error, please file an issue at https://github.com/returntocorp/semgrep-action/issues/new/choose
        and include any log output from above.
        """
        message = dedent(message).strip()
        click.echo("", err=True)
        click.echo(message, err=True)
        sys.exit(error.exit_code)
    after = time.time()

    return Results(findings, after - before)
