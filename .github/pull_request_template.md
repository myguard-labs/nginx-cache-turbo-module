## What and why

<!-- One feature or fix per PR. Link the issue if there is one. -->

## Checklist

- [ ] Tests ship in this PR for the new behaviour or fix.
- [ ] README updated if behaviour changed.
- [ ] New or changed park: TSV row in `ci/park-sites.tsv`, handler swap (only
      for access/precontent parks), detach (unless the TSV detach column is
      `none`), `CT_PARK_*` macros, abort arms, finalize-before-posted order
      (or: no park touched).
