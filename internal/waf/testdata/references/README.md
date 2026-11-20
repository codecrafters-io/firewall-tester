# WAF reference fixtures

The course publishes learner solutions only through stage 4. These cumulative
Go and Python fixtures cover stages 5-11 for the tester's positive-reference,
previous-stage rejection, mutation, replay, and CLI checks.

The fixtures originate from course commit
`5625845463587a432710cc9349532892f6353cc2`, before the later-stage solutions were
removed. They follow the current inspection contract, including bare query
parameters as separate inputs. Form fields without `=` retain empty values.

Run the complete checks with `make test` from the tester repository, with the
course checkout beside it or selected by `WAF_COURSE_DIR`. Stage 1-4 references,
the stage definition, and the frozen model still come from the course checkout.

These are test data. The release archive contains only the tester binary and
`test.sh`.
