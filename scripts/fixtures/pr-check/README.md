# Actions response fixtures

Recorded 2026-11-08 using the GitHub Actions REST API. These JSON files are
field projections of real responses; messages, actors, logs and repository
contents are omitted. No conclusions, job names, identities or step outcomes
were changed.

- `41977805327-run.json`: `GET /repos/Subunit-UG/scai-releases/actions/runs/41977805327`
- `41977805327-jobs.json`: `GET /repos/Subunit-UG/scai-releases/actions/runs/41977805327/attempts/1/jobs?per_page=100`
- `42248826208-run.json`: `GET /repos/Subunit-UG/scai-releases/actions/runs/42248826208`
- `workflow.json`: `GET /repos/Subunit-UG/scai-releases/actions/workflows/pr-check.yml`
- `trees.json`: the `tree.sha` fields from `GET /repos/Subunit-UG/scai-app/git/commits/{sha}`.

The first run is successful PR CI. The second is a successful release build,
which cannot serve as PR CI. Its source tree differs from the checked tree.
Additional cases mutate copies in memory and label synthetic identities in
the test. Production resolves trees with Git through the read-only deploy key,
never from these fixtures or from a public workflow's `head_sha`.
