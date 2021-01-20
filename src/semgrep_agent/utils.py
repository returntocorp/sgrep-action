import json
import os
import sys
import urllib.parse
from contextlib import contextmanager
from pathlib import Path
from textwrap import dedent
from textwrap import indent
from typing import cast
from typing import Iterator
from typing import List
from typing import NoReturn
from typing import Optional
from typing import TYPE_CHECKING
from typing import Union

import click
import git as gitpython
import sh
from boltons import ecoutils
from sh.contrib import git

from semgrep_agent import constants

if TYPE_CHECKING:
    from semgrep_agent.meta import GitMeta
    from semgrep_agent.semgrep import SemgrepCommandFailure


def debug_echo(text: str) -> None:
    """Print debug messages with context-specific debug formatting."""
    if os.getenv("SEMGREP_AGENT_DEBUG"):
        prefix = "=== [DEBUG] "
    elif os.getenv("GITHUB_ACTIONS"):
        prefix = "::debug::"
    else:
        return
    text = "\n".join(prefix + line for line in text.splitlines())
    click.echo(text, err=True)


def maybe_print_debug_info(meta: "GitMeta") -> None:
    if not os.getenv("SEMGREP_AGENT_DEBUG"):
        return

    debug_echo("\n== ecosystem profile:")
    debug_echo(json.dumps(ecoutils.get_profile(), indent=2, sort_keys=True))
    debug_echo("\n== meta info:")
    debug_echo(json.dumps(meta.to_dict(), indent=2, sort_keys=True))


def get_git_repo(path: Optional[Path] = None) -> Optional[gitpython.Repo]:  # type: ignore
    try:
        r = gitpython.Repo(str(path or Path.cwd()), search_parent_directories=True)
        return r
    except gitpython.exc.InvalidGitRepositoryError:
        return None


def zsplit(s: str) -> List[str]:
    """Split a string on null characters."""
    s = s.strip("\0")
    if s:
        return s.split("\0")
    else:
        return []


def validate_publish_token(token: str) -> bool:
    return constants.PUBLISH_TOKEN_VALIDATOR.match(token) is not None


@contextmanager
def fix_head_for_github(
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
        base_ref = git(["rev-parse", base_ref]).stdout.decode("utf-8").rstrip()

    if head_ref:
        stashed_rev = git(["branch", "--show-current"]).stdout.decode("utf-8").rstrip()
        if not stashed_rev:
            stashed_rev = git(["rev-parse", "HEAD"]).stdout.decode("utf-8").rstrip()
        click.echo(f"| not on head ref {head_ref}; checking that out now...", err=True)
        git.checkout([head_ref])

    try:
        if base_ref is not None:
            click.echo("| scanning only the following commits:", err=True)
            # fmt:off
            log = git.log(["--oneline", "--graph", f"{base_ref}..HEAD"]).stdout  # type:ignore
            # fmt: on
            rr = cast(bytes, log).decode("utf-8").rstrip().split("\n")
            r = "\n|   ".join(rr)
            click.echo("|   " + r, err=True)

        yield base_ref
    finally:
        if stashed_rev is not None:
            click.echo(f"| returning to original head revision {stashed_rev}", err=True)
            git.checkout([stashed_rev])


SH_ERROR_NEXT_STEPS = (
    "This is an internal error, please file an issue at "
    "https://github.com/returntocorp/semgrep-action/issues/new/choose "
    "and include any log output from above."
)


def exit_with_sh_error(  # type: ignore
    error: Union[sh.ErrorReturnCode, "SemgrepCommandFailure"],
    next_steps: str = SH_ERROR_NEXT_STEPS,
) -> NoReturn:
    message = f"""
    === failed command's STDOUT:

{indent(error.stdout.decode(), 8 * ' ')}

    === failed command's STDERR:

{indent(error.stderr.decode(), 8 * ' ')}

    === [ERROR] `{error.full_cmd}` failed with exit code {error.exit_code}

    {next_steps}
    """
    message = dedent(message).strip()
    click.echo("", err=True)
    click.echo(message, err=True)
    sys.exit(error.exit_code)
