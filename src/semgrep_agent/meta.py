import json
import os
import urllib.parse
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Any
from typing import cast
from typing import Dict
from typing import Optional
from typing import Type
from typing import Union

import git as gitpython
import sh
from boltons.cacheutils import cachedproperty
from glom import glom
from glom import T
from glom.core import TType
from sh.contrib import git

from semgrep_agent.utils import debug_echo


@dataclass
class GitMeta:
    """Gather metadata only from local filesystem."""

    config: str
    cli_baseline_ref: Optional[str] = None
    environment: str = field(default="git", init=False)

    @cachedproperty
    def event_name(self) -> str:
        return "unknown"

    @cachedproperty
    def repo(self) -> gitpython.Repo:  # type: ignore
        repo = gitpython.Repo(".", search_parent_directories=True)
        debug_echo(f"found repo: {repo!r}")
        return repo

    @cachedproperty
    def repo_name(self) -> str:
        if not self.repo.head.is_valid():
            raise RuntimeError("Semgrep action cannot run on repository with no HEAD")
        return os.getenv("SEMGREP_REPO_NAME") or str(
            os.path.basename(self.repo.working_tree_dir)
        )

    @cachedproperty
    def repo_url(self) -> Optional[str]:
        return os.getenv("SEMGREP_REPO_URL")

    @cachedproperty
    def commit_sha(self) -> Optional[str]:
        return self.repo.head.commit.hexsha  # type: ignore

    @cachedproperty
    def head_ref(self) -> Optional[str]:
        return None

    @cachedproperty
    def base_commit_ref(self) -> Optional[str]:
        return self.cli_baseline_ref

    @cachedproperty
    def commit(self) -> gitpython.Commit:  # type: ignore
        commit = self.repo.commit(self.commit_sha)
        debug_echo(f"found commit: {commit!r}")
        return commit

    @cachedproperty
    def branch(self) -> Optional[str]:
        try:
            br = self.repo.active_branch.name
        except:
            br = None
        return os.getenv("SEMGREP_BRANCH") or br

    @cachedproperty
    def ci_job_url(self) -> Optional[str]:
        return os.getenv("SEMGREP_JOB_URL")

    @cachedproperty
    def pr_id(self) -> Optional[str]:
        return os.getenv("SEMGREP_PR_ID")

    @cachedproperty
    def pr_title(self) -> Optional[str]:
        return os.getenv("SEMGREP_PR_TITLE")

    def to_dict(self) -> Dict[str, Any]:
        return {
            # REQUIRED for semgrep-app backend
            "repository": self.repo_name,
            #  OPTIONAL for semgrep-app backend
            "repo_url": self.repo_url,
            "branch": self.branch,
            "ci_job_url": self.ci_job_url,
            "commit": self.commit_sha,
            "commit_author_email": self.repo.head.commit.author.email,
            "commit_author_name": self.repo.head.commit.author.name,
            "commit_author_username": None,
            "commit_author_image_url": None,
            "commit_title": self.commit.summary,
            "config": self.config,
            "on": self.event_name,
            "pull_request_author_username": None,
            "pull_request_author_image_url": None,
            "pull_request_id": self.pr_id,
            "pull_request_title": self.pr_title,
        }


@dataclass
class GithubMeta(GitMeta):
    """Gather metadata from GitHub Actions."""

    environment: str = field(default="github-actions", init=False)

    def glom_event(self, spec: TType) -> Any:
        return glom(self.event, spec, default=None)

    @cachedproperty
    def event(self) -> Dict[str, Any]:
        value = os.getenv("GITHUB_EVENT_PATH")
        if value:
            debug_echo(f"found github event data at {value}")
            return json.loads(Path(value).read_text())  # type: ignore
        return {}

    @cachedproperty
    def repo_name(self) -> Optional[str]:
        return os.getenv("GITHUB_REPOSITORY", "[unknown]")

    @cachedproperty
    def repo_url(self) -> Optional[str]:
        if self.repo_name:
            return f"https://github.com/{self.repo_name}"
        return None

    @cachedproperty
    def commit_sha(self) -> Optional[str]:
        if self.event_name == "pull_request":
            # https://github.community/t/github-sha-not-the-same-as-the-triggering-commit/18286/2
            return self.glom_event(T["pull_request"]["head"]["sha"])  # type: ignore
        if self.event_name == "push":
            return os.getenv("GITHUB_SHA")
        return super().commit_sha  # type: ignore

    @cachedproperty
    def head_ref(self) -> Optional[str]:
        if self.event_name == "pull_request":
            return self.commit_sha  # type: ignore
        else:
            return None

    @cachedproperty
    def base_commit_ref(self) -> Optional[str]:
        if self.cli_baseline_ref:
            return self.cli_baseline_ref
        if self.event_name == "pull_request" and self.head_ref is not None:
            # The pull request "base" that GitHub sends us is not necessarily the merge base,
            # so we need to get the merge-base from Git
            pr_base = self.glom_event(T["pull_request"]["base"]["sha"])
            return git("merge-base", pr_base, self.head_ref).stdout.decode().strip()
        return None

    @cachedproperty
    def commit_ref(self) -> Optional[str]:
        return os.getenv("GITHUB_REF")

    @cachedproperty
    def ci_actor(self) -> Optional[str]:
        return os.getenv("GITHUB_ACTOR")

    @cachedproperty
    def ci_job_url(self) -> Optional[str]:
        value = os.getenv("GITHUB_RUN_ID")
        if self.repo_url and value:
            return f"{self.repo_url}/actions/runs/{value}"
        return None

    @cachedproperty
    def event_name(self) -> str:
        return os.getenv("GITHUB_EVENT_NAME", "unknown")

    @cachedproperty
    def pr_id(self) -> Optional[str]:
        pr_id = self.glom_event(T["pull_request"]["number"])
        return str(pr_id) if pr_id else None

    @cachedproperty
    def pr_title(self) -> Optional[str]:
        pr_title = self.glom_event(T["pull_request"]["title"])
        return str(pr_title) if pr_title else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            **super().to_dict(),
            "branch": self.commit_ref,
            "commit_author_username": self.glom_event(T["sender"]["login"]),
            "commit_author_image_url": self.glom_event(T["sender"]["avatar_url"]),
            "pull_request_author_username": self.glom_event(
                T["pull_request"]["user"]["login"]
            ),
            "pull_request_author_image_url": self.glom_event(
                T["pull_request"]["user"]["avatar_url"]
            ),
        }


@dataclass
class GitlabMeta(GitMeta):
    """Gather metadata from GitLab 10.0+"""

    environment: str = field(default="gitlab-ci", init=False)

    @staticmethod
    def _get_remote_url() -> str:
        parts = urllib.parse.urlsplit(os.environ["CI_MERGE_REQUEST_PROJECT_URL"])
        parts = parts._replace(
            netloc=f"gitlab-ci-token:{os.environ['CI_JOB_TOKEN']}@{parts.netloc}"
        )
        return urllib.parse.urlunsplit(parts)

    @cachedproperty
    def repo_name(self) -> str:
        return os.getenv("CI_PROJECT_PATH", "[unknown]")

    @cachedproperty
    def repo_url(self) -> Optional[str]:
        return os.getenv("CI_PROJECT_URL")

    @cachedproperty
    def commit_sha(self) -> Optional[str]:
        return os.getenv("CI_COMMIT_SHA")

    @cachedproperty
    def commit_ref(self) -> Optional[str]:
        return os.getenv("CI_COMMIT_REF_NAME")

    @cachedproperty
    def base_commit_ref(self) -> Optional[str]:
        if self.cli_baseline_ref:
            return self.cli_baseline_ref
        target_branch = os.getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
        if not target_branch:
            return None
        head_sha = git("rev-parse", "HEAD").stdout.strip()
        git.fetch(self._get_remote_url(), target_branch)
        base_sha = (
            git("merge-base", "--all", head_sha, "FETCH_HEAD").stdout.decode().strip()
        )
        return base_sha

    @cachedproperty
    def ci_actor(self) -> Optional[str]:
        return os.getenv("GITLAB_USER_LOGIN")

    @cachedproperty
    def ci_job_url(self) -> Optional[str]:
        return os.getenv("CI_JOB_URL")

    @cachedproperty
    def event_name(self) -> str:
        return os.getenv("CI_PIPELINE_SOURCE", "unknown")

    @cachedproperty
    def pr_id(self) -> Optional[str]:
        return os.getenv("CI_MERGE_REQUEST_IID")

    @cachedproperty
    def pr_title(self) -> Optional[str]:
        return os.getenv("CI_MERGE_REQUEST_TITLE")


def detect_meta_environment() -> Type[GitMeta]:
    # https://help.github.com/en/actions/configuring-and-managing-workflows/using-environment-variables
    if os.getenv("GITHUB_ACTIONS") == "true":
        return GithubMeta

    # https://circleci.com/docs/2.0/env-vars/#built-in-environment-variables
    elif os.getenv("CIRCLECI") == "true":  # nosem
        return GitMeta

    # https://docs.travis-ci.com/user/environment-variables/#default-environment-variables
    elif os.getenv("TRAVIS") == "true":  # nosem
        return GitMeta

    # https://docs.gitlab.com/ee/ci/variables/predefined_variables.html
    elif os.getenv("GITLAB_CI") == "true":
        return GitlabMeta

    elif os.getenv("CI"):  # nosem
        return GitMeta

    else:  # nosem
        return GitMeta
