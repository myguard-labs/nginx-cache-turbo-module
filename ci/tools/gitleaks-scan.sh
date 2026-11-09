#!/usr/bin/env bash
set -euo pipefail

if [ "${GITHUB_EVENT_NAME:-}" = pull_request ]; then
	for sha in "${PR_BASE_SHA:-}" "${PR_HEAD_SHA:-}"; do
		if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]] || ! git cat-file -e "${sha}^{commit}"; then
			echo 'Invalid or missing PR commit bound' >&2
			exit 1
		fi
	done
	git merge-base "$PR_BASE_SHA" "$PR_HEAD_SHA" >/dev/null
	exec "${GITLEAKS_BIN:-gitleaks}" git --no-banner --redact --log-opts="$PR_BASE_SHA..$PR_HEAD_SHA" .
fi
exec "${GITLEAKS_BIN:-gitleaks}" git --no-banner --redact .
