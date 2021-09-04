
# For MRs we use $CI_MERGE_REQUEST_SOURCE_BRANCH_NAME
# For master we use $CI_COMMIT_BEFORE_SHA

source .gitlab-ci/config.env

TMP_DIFF_FILE="/tmp/changes.diff"

if [ -z "$GIT_UPSTREAM" ]; then
	echo "==> Can't get git upstream URL"
	exit 1
fi

git remote add upstream "$GIT_UPSTREAM"
git fetch upstream

# This will be valid in branch pipelines (not in MRs)
if [ "$CI_COMMIT_BEFORE_SHA" != "0000000000000000000000000000000000000000" ]; then
	COMMIT_SHA="$CI_COMMIT_BEFORE_SHA"
else
	UPSTREAM_BRANCH="$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
	COMMIT_SHA="$(git rev-parse upstream/$UPSTREAM_BRANCH)"
fi

git clang-format $COMMIT_SHA
git --no-pager diff > "$TMP_DIFF_FILE"
if [ $(wc -l "$TMP_DIFF_FILE" | cut -d" " -f1) -gt 0 ]; then
	echo
	echo "==> clang-format suggested the following changes:"
	echo
	cat "$TMP_DIFF_FILE"
	exit 1
else
	echo "No formatting issues!"
fi

exit 0
