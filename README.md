# Inbound WAF course tester

The active tester for **Build your own Web Application Firewall** uses `internal/waf` and the stable course slug `firewall`. Keep this repository beside `build-your-own-firewall`, or set `WAF_COURSE_DIR` to the course checkout when running reference checks.

```text
External client -> Learner WAF -> Local application origin
                         |
                         +----> Scripted ML detector
```

## Run locally

The reference checks use Go and the Python starter's `uv` launcher (Python 3.14). They start local listeners on port 8080, so stop any other learner process first.

```sh
make copy_course_file
make test
make build
```

Each new stage is checked against its corresponding Go and Python reference. The preceding Python reference must fail the next stage's new control. The final stage repeats the earlier contract cases in addition to checking the virtual patch.

`test.sh` and `cmd/tester` use the new WAF grader. It observes original request bytes, origin request counts, response status/body/headers, detector calls, timeout fallback, body-validation failures, spoofed diagnostics, route decisions, fixed-window rate limits, concurrent bursts, response leaks, and private-field export patches. No model-proposed tools are executed.

The ML detector fixtures return deterministic scores. The course repository separately supplies a frozen real classifier, training source, held-out examples, and observed evaluation results. These are distinct checks of integration and model behavior.

## Migration status

The previous AI gateway grader and fixtures remain under `internal` to preserve the existing uncommitted work during this conversion. They are historical and are not selected by the active tester entry point or `make test`. Their former stage Make targets have been removed. Cleanup of those files can follow the coordinated migration commit.

The published v1 tester predates this inbound curriculum. Publish a coordinated tester release before rolling out the new course; local verification does not change the hosted grader.

## Release verification

The Test workflow accepts a `course_ref` input for checking a coordinated course
commit or branch before merging. It now includes regressions for all supported
methods, exact fired-signal IDs, total detector deadlines (including trickled
headers and bodies), incomplete origin responses, and empty inspected bodies.
It also runs the frozen model checks and the real final-stage CLI in Go and
Python. The Publish workflow requires these checks against the course's `main`
branch before creating release artifacts.

Follow the course repository's `RELEASING.md` to coordinate publication and the
hosted tester selection. Passing local checks does not publish a new tester.
