from typing import Any, Callable, Union

class ErrorReturnCode(Exception):
    @property
    def full_cmd(self) -> str: ...
    @property
    def exit_code(self) -> int: ...
    @property
    def stdout(self) -> bytes: ...
    @property
    def stderr(self) -> bytes: ...

class GitSubcommandsMixin:

    # git subcommands
    @property
    def checkout(self) -> Command: ...
    @property
    def diff(self) -> Command: ...
    @property
    def fetch(self) -> Command: ...
    @property
    def rm(self) -> Command: ...
    @property
    def status(self) -> Command: ...

class Command(GitSubcommandsMixin):
    def __call__(self, *args: Any, **kwargs: Any) -> RunningCommand: ...
    def bake(self, *args: Any, **kwargs: Any) -> Command: ...

class RunningCommand(str, GitSubcommandsMixin):
    @property
    def stdout(self) -> bytes: ...
    @property
    def stderr(self) -> bytes: ...
    @property
    def exit_code(self) -> int: ...

semgrep: Command
python: Command
