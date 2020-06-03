import sys
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Optional

import click
import requests
from boltons.iterutils import chunked_iter

from .bento import Results
from .utils import debug_echo


@dataclass
class Sapp:
    ctx: click.Context
    url: str
    token: str
    deployment_id: int
    scan_id: Optional[int] = None
    is_configured: bool = False
    session: requests.Session = field(init=False)

    def __post_init__(self) -> None:
        if self.token and self.deployment_id:
            self.is_configured = True
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {self.token}"

    def report_start(self) -> None:
        if not self.is_configured:
            debug_echo("== no semgrep app config, skipping report_start")
            return
        debug_echo(f"== reporting start to semgrep app at {self.url}")

        response = self.session.post(
            f"{self.url}/api/agent/deployment/{self.deployment_id}/scan",
            json={"meta": self.ctx.obj.meta.to_dict()},
            timeout=30,
        )
        debug_echo(f"== POST .../scan responded: {response!r}")
        try:
            response.raise_for_status()
        except requests.RequestException:
            click.echo(f"Semgrep App returned this error: {response.text}", err=True)
        else:
            self.scan_id = response.json()["scan"]["id"]

    def fetch_rules_text(self) -> str:
        """Get a YAML string with the configured semgrep rules in it."""
        if self.scan_id is None:
            raise RuntimeError("sapp is configured so we should've gotten a scan_id")

        try:
            response = self.session.get(
                f"{self.url}/api/agent/scan/{self.scan_id}/rules.yaml", timeout=30,
            )
            debug_echo(f"== POST .../rules.yaml responded: {response!r}")
            response.raise_for_status()
        except requests.RequestException:
            click.echo(f"Semgrep App returned this error: {response.text}", err=True)
            click.echo("Failed to get configured rules", err=True)
            sys.exit(1)
        else:
            return response.text

    def download_rules(self) -> None:
        """Save the rules configured on semgrep app to .bento/semgrep.yml"""
        Path(".bento").mkdir(exist_ok=True)
        (Path(".bento") / "semgrep.yml").write_text(self.fetch_rules_text())

    def report_results(self, results: Results) -> None:
        if not self.is_configured or self.scan_id is None:
            debug_echo("== no semgrep app config, skipping report_results")
            return
        debug_echo(f"== reporting results to semgrep app at {self.url}")

        # report findings
        if results.findings is None:
            raise RuntimeError(
                "sapp is configured so we should've decided to run bento --json"
            )
        for chunk in chunked_iter(results.findings, 10_000):
            response = self.session.post(
                f"{self.url}/api/agent/scan/{self.scan_id}/findings",
                json=chunk,
                timeout=30,
            )
            debug_echo(f"== POST .../findings responded: {response!r}")
            try:
                response.raise_for_status()
            except requests.RequestException:
                click.echo(
                    f"Semgrep App returned this error: {response.text}", err=True
                )

        # mark as complete
        try:
            response = self.session.post(
                f"{self.url}/api/agent/scan/{self.scan_id}/complete",
                json={"exit_code": results.exit_code, "stats": results.stats},
                timeout=30,
            )
            debug_echo(f"== POST .../complete responded: {response!r}")
            response.raise_for_status()
        except requests.RequestException:
            click.echo(f"Semgrep App returned this error: {response.text}", err=True)
