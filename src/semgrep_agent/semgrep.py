import asyncio
import io
import json
import os
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Sequence
from typing import TextIO

import click
import sh
from boltons.iterutils import chunked_iter
from boltons.strutils import unit_len
from sh.contrib import git

from semgrep_agent.exc import ActionFailure
from semgrep_agent.findings import Finding
from semgrep_agent.findings import FindingSets
from semgrep_agent.postprocessing import postprocess
from semgrep_agent.targets import TargetFileManager
from semgrep_agent.utils import debug_echo
from semgrep_agent.utils import get_git_repo
from semgrep_agent.utils import is_debug
from semgrep_agent.utils import print_git_log

ua_environ = {"SEMGREP_USER_AGENT_APPEND": "(Agent)", **os.environ}
semgrep_exec = sh.semgrep.bake(_ok_code={0, 1}, _tty_out=False, _env=ua_environ)

# a typical old system has 128 * 1024 as their max command length
# we assume an average ~250 characters for a path in the worst case
PATHS_CHUNK_SIZE = 500


def resolve_config_shorthand(config: str) -> str:
    maybe_prefix = config[:2]
    if maybe_prefix in {"p/", "r/", "s/"}:
        return f"https://semgrep.dev/c/{config}"
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


def get_findings(
    config_specifier: Sequence[str],
    committed_datetime: Optional[datetime],
    base_commit_ref: Optional[str],
    head_ref: Optional[str],
    semgrep_ignore: TextIO,
    rewrite_rule_ids: bool,
    enable_metrics: bool,
    *,
    timeout: Optional[int],
) -> FindingSets:
    debug_echo("=== adding semgrep configuration")

    with _fix_head_for_github(base_commit_ref, head_ref) as base_ref:
        workdir = Path.cwd()
        targets = TargetFileManager(
            base_path=workdir,
            base_commit=base_ref,
            all_paths=[workdir],
            ignore_rules_file=semgrep_ignore,
        )

        config_args = []
        local_configs = (
            set()
        )  # Keep track of which config specifiers are local files/dirs
        for conf in config_specifier:
            if Path(conf).exists():
                local_configs.add(conf)
            config_args.extend(["--config", conf])
        rewrite_args = [] if rewrite_rule_ids else ["--no-rewrite-rule-ids"]
        metrics_args = ["--enable-metrics"] if enable_metrics else []
        debug_echo("=== seeing if there are any findings")
        findings = FindingSets(searched_paths=set(targets.searched_paths))

        with targets.current_paths() as paths:
            click.echo(
                "=== looking for current issues in " + unit_len(paths, "file"), err=True
            )

            for path in paths:
                debug_echo(f"searching {str(path)}")

            args = [
                "--skip-unknown-extensions",
                "--disable-nosem",
                "--json",
                "--autofix",
                "--dryrun",
                *metrics_args,
                *rewrite_args,
                *config_args,
            ]
            semgrep_results = invoke_semgrep(
                args, [str(p) for p in paths], timeout=timeout
            )["results"]

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
            paths_to_check = list(
                set(str(path) for path in paths) & paths_with_findings
            )
            if not paths_to_check:
                click.echo(
                    "=== not looking at pre-existing issues since all files with current issues are newly created",
                    err=True,
                )
            else:
                config_args = []
                for conf in config_specifier:
                    # If a local config existed with initial scan but doesn't exist
                    # in baseline, treat as if no issues found in baseline with that config
                    if conf in local_configs and not Path(conf).exists():
                        click.echo(
                            f"=== {conf} file not found in baseline, skipping scanning for baseline",
                            err=True,
                        )
                        continue
                    config_args.extend(["--config", conf])

                if config_args == []:
                    click.echo(
                        "=== not looking at pre-exiting issues since after filtering out local files that don't exist in baseline, no configs left to run",
                        err=True,
                    )
                else:
                    click.echo(
                        "=== looking for pre-existing issues in "
                        + unit_len(paths_to_check, "file"),
                        err=True,
                    )

                    args = [
                        "--skip-unknown-extensions",
                        "--json",
                        "--disable-metrics",  # only count one semgrep run per semgrep-agent run
                        *rewrite_args,
                        *config_args,
                    ]
                    semgrep_results = invoke_semgrep(
                        args, paths_to_check, timeout=timeout
                    )["results"]
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
                args.extend(["--include", str(path)])
            semgrep_exec(*args, _out=sarif_file, _timeout=timeout)
        rewrite_sarif_file(sarif_path)

    return findings


def invoke_semgrep(
    semgrep_args: List[str], targets: List[str], *, timeout: Optional[int]
) -> Dict[str, List[Any]]:
    """
    Call semgrep passing in semgrep_args + targets as the arguments

    Returns json output of semgrep as dict object
    """
    output: Dict[str, List[Any]] = {"results": [], "errors": []}

    for chunk in chunked_iter(targets, PATHS_CHUNK_SIZE):
        with tempfile.NamedTemporaryFile("w") as output_json_file:
            args = semgrep_args.copy()
            if is_debug():
                args.extend(["--debug"])
            args.extend(
                [
                    "-o",
                    output_json_file.name,  # nosem: python.lang.correctness.tempfile.flush.tempfile-without-flush
                ]
            )
            for c in chunk:
                args.append(c)

            _ = semgrep_exec(*args, _timeout=timeout, _err=debug_echo)

            with open(
                output_json_file.name  # nosem: python.lang.correctness.tempfile.flush.tempfile-without-flush
            ) as f:
                parsed_output = json.load(f)

            output["results"].extend(parsed_output["results"])
            output["errors"].extend(parsed_output["errors"])

    output["results"] = postprocess(output["results"])

    return output


class SemgrepError(Exception):
    def __init__(self, error: sh.ErrorReturnCode):
        self._exit_code = error.exit_code
        self._stdout = error.stdout.decode()
        self._stderr = error.stderr.decode()
        self._command = error.full_cmd

    @property
    def exit_code(self) -> int:
        return self._exit_code

    @property
    def stdout(self) -> str:
        return self._stdout

    @property
    def stderr(self) -> str:
        return self._stderr

    @property
    def command(self) -> str:
        return self._command


def scan(
    config_specifier: Sequence[str],
    committed_datetime: Optional[datetime],
    base_commit_ref: Optional[str],
    head_ref: Optional[str],
    semgrep_ignore: TextIO,
    rewrite_rule_ids: bool,
    enable_metrics: bool,
    *,
    timeout: Optional[int],
) -> Results:
    before = time.time()
    try:
        findings = get_findings(
            config_specifier,
            committed_datetime,
            base_commit_ref,
            head_ref,
            semgrep_ignore,
            rewrite_rule_ids,
            enable_metrics,
            timeout=timeout,
        )
    except sh.ErrorReturnCode as error:
        raise SemgrepError(error)
    after = time.time()

    return Results(findings, after - before)


@contextmanager
def _fix_head_for_github(
    base_commit_ref: Optional[str] = None,
    head_ref: Optional[str] = None,
) -> Iterator[Optional[str]]:
    """
    GHA can checkout the incorrect commit for a PR (it will create a fake merge commit),
    so we need to reset the head to the actual PR branch head before continuing.

    Note that this code is written in a generic manner, so that it becomes a no-op when
    the CI system has not artifically altered the HEAD ref.

    :return: The baseline ref as a commit hash
    """

    stashed_rev: Optional[str] = None
    base_ref: Optional[str] = base_commit_ref

    if get_git_repo() is None:
        yield base_ref
        return

    if base_ref:
        # Preserve location of head^ after we possibly change location below
        try:
            process = git(["rev-parse", base_ref])
            base_ref = process.stdout.decode("utf-8").rstrip()
        except sh.ErrorReturnCode as ex:
            raise ActionFailure(f"There is a problem with your git project:{ex}")

    if head_ref:
        stashed_rev = git(["branch", "--show-current"]).stdout.decode("utf-8").rstrip()
        if not stashed_rev:
            stashed_rev = git(["rev-parse", "HEAD"]).stdout.decode("utf-8").rstrip()
        click.echo(f"| not on head ref {head_ref}; checking that out now...", err=True)
        git.checkout([head_ref], _timeout=300, _out=debug_echo, _err=debug_echo)
        debug_echo(f"checked out {head_ref}")

    try:
        if base_ref is not None:
            merge_base = git("merge-base", base_ref, "HEAD").rstrip()
            # fmt:off
            click.echo("| reporting findings introduced by these commits:", err=True)
            print_git_log(f"{merge_base}..HEAD")
            if merge_base != git("rev-parse", base_ref).rstrip():
                click.echo("| also reporting findings fixed by these commits from the baseline branch:", err=True)
                print_git_log(f"{merge_base}..{base_ref}")
                click.echo("| to exclude these latter commits, run with", err=True)
                click.echo(f"|   --baseline-ref $(git merge-base {base_commit_ref} HEAD)", err=True)
            # fmt: on

        yield base_ref
    finally:
        if stashed_rev is not None:
            click.echo(f"| returning to original head revision {stashed_rev}", err=True)
            git.checkout([stashed_rev])
