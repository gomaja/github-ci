# github-ci Go canary seed

This repository seed exercises two Go modules, two simultaneous build tags,
generated-source classification, non-default package and coverage scopes,
module modes, timeouts, and package and race parallelism.

Copy the seed into a dedicated public repository, run
`scripts/check-generated.sh`, and render the standard and deep caller workflows
at the exact candidate commit. Do not replace the candidate commit with a tag
or branch.
