# Semgrep CI

<p align="center">
  <a href="https://r2c.dev/slack">
      <img src="https://img.shields.io/badge/Slack-700%2B%20members-black" alt="Slack invite" />
  </a>
  <a href="https://semgrep.dev/docs/semgrep-ci/">
      <img src="https://img.shields.io/badge/docs-semgrep.dev-purple" alt="Documentation" />
  </a>
  <a href="https://github.com/returntocorp/semgrep-action/actions/workflows/test.yml">
      <img src="https://github.com/returntocorp/semgrep-action/actions/workflows/test.yml/badge.svg" alt="Tests status" />
  </a>
  <a href="https://hub.docker.com/r/returntocorp/semgrep-agent">
    <img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/returntocorp/semgrep-agent">
  </a>
</p>

Semgrep CI (aka Semgrep Action or `semgrep-agent`) is a specialized Docker image for running [Semgrep](https://github.com/returntocorp/semgrep) in CI environments. It can also optionally connect to [Semgrep App](https://semgrep.dev/login) for centralized rule and findings management.

- **Scan every commit.** Semgrep CI rapidly scans modified files on pull and merge requests, protecting developer productivity. Longer full project scans are configurable on merges to specific branches.
- **Block new bugs.** You shouldn’t have to fix existing bugs just to adopt a tool. Semgrep CI reports newly introduced issues on pull and merge requests, scanning them at their base and HEAD commits to compare findings. Developers are signficantly more likely to fix the issues they introduced themselves on PRs and MRs.
- **Get findings where you work.** Semgrep CI can connect to Semgrep App to present findings in Slack, on PRs and MRs via inline comments, email, and through 3rd party services.

> Semgrep CI runs fully in your build environment: code is never sent anywhere.

## Getting started

Semgrep CI behaves like other static analysis and linting tools:
it runs a set of user-configured rules and returns a non-zero exit code if there are findings,
resulting in its job showing a ✅ or ❌.

Find a relevant template for your CI provider through these links:

- [**GitHub Actions**](https://semgrep.dev/docs/semgrep-ci/#github-actions)
- [**GitLab CI/CD**](https://semgrep.dev/docs/semgrep-ci/#gitlab-cicd)
- [**Other CI providers**](https://semgrep.dev/docs/semgrep-ci/#other-ci-providers) (Buildkite, CircleCI, Jenkins, and more)

Read through the comments in the template to adjust when and what Semgrep CI scans, selecting pull and merge requests, merges to branches, or both.

Once Semgrep CI is running, [explore the Semgrep Registry](https://semgrep.dev/explore) to find and add more project-specific rules.

## Configuration

See [Advanced Configuration documentation](https://semgrep.dev/docs/semgrep-ci/#advanced-configuration) for further customizations, such as scanning with custom rules, ignoring files, and tuning performance.

## Metrics

Semgrep CI collects opt-out non-identifiable aggregate metrics for improving the user experience, guiding Semgrep feature development, and identifying regressions.

The [`PRIVACY.md`](PRIVACY.md) file describes the principles that guide our data-collection decisions, the breakdown of the data that are and are not collected, and how to opt-out of Semgrep CI’s metrics.

> Semgrep CI never sends your source code anywhere.

## Technical details

### Packaging

Semgrep CI is published under the name `semgrep-agent`.

- The [`semgrep_agent` Python package](https://github.com/returntocorp/semgrep-action/tree/develop/src/semgrep_agent) uses this name.
- The [`semgrep-agent` Docker image](https://hub.docker.com/r/returntocorp/semgrep-agent) also uses this name.
- The [semgrep-action](https://github.com/marketplace/actions/semgrep-action) GitHub Marketplace listing
  runs the above Docker image.
- The [semgrep-action repository](https://github.com/returntocorp/semgrep-action)
  holds the code for Semgrep CI, the Docker image, and the GitHub Marketplace manifest.

New versions of Semgrep CI and the Docker image above are released by Semgrep maintainers on a regular basis. To run all jobs with the latest releases, use `returntocorp/semgrep-action@v1` in your GitHub Actions workflow, or the `returntocorp/semgrep-agent:v1` Docker image with other providers.

> The Python package itself is not published to PyPI,
> or any other package index,
> but you can still use it by cloning the GitHub repository.

### Usage outside CI

While Semgrep CI is designed
for integrating with various CI providers,
it's versatile enough to be used locally
to scan a repository with awareness of its git history.

To locally scan issues in your current branch
that are not found on the `main` branch,
run the following command:

```sh
docker run -v $(pwd):/src --workdir /src returntocorp/semgrep-agent:v1 semgrep-agent --config p/ci --baseline-ref main
```

Another use case is when you want to scan only commits
from the past weeks for new issues they introduced.
This can be done by using a git command
that gets the tip of the current branch two weeks earlier:

```sh
docker run -v $(pwd):/src --workdir /src returntocorp/semgrep-agent:v1 semgrep-agent --config p/ci --baseline-ref $(git rev-parse '@{2.weeks.ago}')
```

To compare two commits
and find the issues added between them,
checkout the more recent commit of the two
before running Semgrep CI:

```sh
git checkout $RECENT_SHA
docker run -v $(pwd):/src --workdir /src returntocorp/semgrep-agent:v1 semgrep-agent --config p/ci --baseline-ref $OLDER_SHA
```

> The above commands all require `docker`
> to be installed on your machine.
> They also use Docker volumes
> to make your working directory accessible to the container.
> `--config p/ci` is the Semgrep rule configuration,
> which can be changed to any value
> that `semgrep` itself understands.

## EXPERIMENTAL: `.semgrepconfig.yml` overrides

You can add a `.semgrepconfig.yml` that looks like this:

```yaml
overrides:
  - if.path: "tests/*" # the first two lines in this example are "conditions"
    if.rule_id: "secrets.*aws*"
    mute: true # this last line in this example is an "action"

  - if.policy_slug: "*important*"
    if.severity_in: ["ERROR"]
    unmute: true # report issues even if they were muted with # nosemgrep
    set_severity: WARNING # but lower their severity a bit
```

Every finding will be checked against these override definitions one by one.
The override definitions will run in the same order you have them in your config file.

An override's actions are applied when all `if.` conditions are true. If an override applies, it'll take actions as described by keys not starting with `if.*`.

### Available conditions

| key              | example value         | `True` if the finding's…                        |
| ---------------- | --------------------- | ----------------------------------------------- |
| `if.path`        | `"tests/*"`           | path matches the given glob                     |
| `if.rule_id`     | `"secrets.*aws*"`     | rule ID matches the given glob                  |
| `if.ruleset_id`  | `"secrets"`           | rule is from a ruleset matching the given glob  |
| `if.finding_id`  | `"1fd8aac00"`         | finding's `syntactic_id` starts with this value |
| `if.policy_slug` | `"security*"`         | rule is from a policy matching the given glob   |
| `if.severity_in` | `["INFO", "WARNING"]` | rule's severity is in the given list            |

### Available actions

| key            | example value | description                                     |
| -------------- | ------------- | ----------------------------------------------- |
| `mute`         | `true`        | acts as if the line had a `# nosemgrep` comment |
| `unmute`       | `true`        | ignores any `# nosemgrep` comments              |
| `set_severity` | `"INFO"`      | changes the reported severity of the issue      |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)
