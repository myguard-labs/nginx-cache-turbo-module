# essentials fixtures

Inputs for the `lint-astgrep-essentials.sh` cases in `ci/linter/selftest.sh`.
Do not fix them: `error.lua` must keep one error-severity hit, `warning.lua`
only warnings, `clean.lua` none. Lua because nothing else here lints Lua.
