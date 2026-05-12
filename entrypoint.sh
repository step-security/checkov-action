#!/bin/bash

# --- StepSecurity subscription check (begin) ---
REPO_PRIVATE=$(jq -r '.repository.private | tostring' "$GITHUB_EVENT_PATH" 2>/dev/null || echo "")
UPSTREAM="bridgecrewio/checkov-action"
ACTION_REPO="${GITHUB_ACTION_REPOSITORY:-}"
DOCS_URL="https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions"

echo ""
echo -e "\033[1;36mStepSecurity Maintained Action\033[0m"
echo "Secure drop-in replacement for $UPSTREAM"
if [ "$REPO_PRIVATE" = "false" ]; then
  echo -e "\033[32m✓ Free for public repositories\033[0m"
fi
echo -e "\033[36mLearn more:\033[0m $DOCS_URL"
echo ""

if [ "$REPO_PRIVATE" != "false" ]; then
  SERVER_URL="${GITHUB_SERVER_URL:-https://github.com}"

  if [ "$SERVER_URL" != "https://github.com" ]; then
    BODY=$(printf '{"action":"%s","ghes_server":"%s"}' "$ACTION_REPO" "$SERVER_URL")
  else
    BODY=$(printf '{"action":"%s"}' "$ACTION_REPO")
  fi

  API_URL="https://agent.api.stepsecurity.io/v1/github/$GITHUB_REPOSITORY/actions/maintained-actions-subscription"

  RESPONSE=$(curl --max-time 3 -s -w "%{http_code}" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$BODY" \
    "$API_URL" -o /dev/null) && CURL_EXIT_CODE=0 || CURL_EXIT_CODE=$?

  if [ $CURL_EXIT_CODE -ne 0 ]; then
    echo "Timeout or API not reachable. Continuing to next step."
  elif [ "$RESPONSE" = "403" ]; then
    echo -e "::error::\033[1;31mThis action requires a StepSecurity subscription for private repositories.\033[0m"
    echo -e "::error::\033[31mLearn how to enable a subscription: $DOCS_URL\033[0m"
    exit 1
  fi
fi

# Defense-in-depth: warn if --user value (positional arg) contains unexpected characters.
prev_arg=""
for arg in "$@"; do
  if [ "$prev_arg" = "--user" ]; then
    if ! [[ "$arg" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*(:[A-Za-z0-9_][A-Za-z0-9_.-]*)?$ ]]; then
      echo "::warning::Suspicious container_user value detected. Expected a UID/username, optionally followed by :GID/:groupname, e.g. 1000, 1000:1000, nobody, myuser:mygroup."
    fi
  fi
  prev_arg="$arg"
done
# --- StepSecurity subscription check (end) ---

# Leverage the default env variables as described in:
# https://docs.github.com/en/actions/reference/environment-variables#default-environment-variables
if [[ $GITHUB_ACTIONS != "true" ]]
then
  checkov "$@"
  exit $?
fi

matcher_path=`pwd`/checkov-problem-matcher.json
warning_matcher_path=`pwd`/checkov-problem-matcher-softfail.json
cp /usr/local/lib/checkov-problem-matcher.json "$matcher_path"
cp /usr/local/lib/checkov-problem-matcher-softfail.json "$warning_matcher_path"

export BC_SOURCE=githubActions

if [ -n "$PRISMA_API_URL" ]; then
  export PRISMA_API_URL="$PRISMA_API_URL"
fi

# Build checkov argv as a bash array so each INPUT_* value is exactly one
# argv element. 
declare -a CKV_ARGS=()

add_flag() {
  # add_flag --flag "$VALUE"  -> appends iff VALUE is non-empty
  local flag="$1" val="$2"
  [[ -n "$val" ]] && CKV_ARGS+=("$flag" "$val")
}

add_bool() {
  # add_bool --flag "$VALUE"  -> appends flag iff VALUE == "true"
  local flag="$1" val="$2"
  [[ "$val" == "true" ]] && CKV_ARGS+=("$flag")
}

add_csv() {
  # add_csv --flag "$CSV"  -> one flag per comma-separated token
  local flag="$1" csv="$2"
  [[ -z "$csv" ]] && return
  local IFS=','
  local -a parts
  read -r -a parts <<< "$csv"
  local p
  for p in "${parts[@]}"; do
    p="${p## }"; p="${p%% }"  # trim single leading/trailing space
    [[ -n "$p" ]] && CKV_ARGS+=("$flag" "$p")
  done
}

add_space_list() {
  # add_space_list --flag "$VAL"  -> split by comma or space, all tokens
  # as positional args after a single flag (for nargs='+' params)
  local flag="$1" val="$2"
  [[ -z "$val" ]] && return
  # Replace commas with spaces, then split on whitespace
  val="${val//,/ }"
  local -a parts
  read -r -a parts <<< "$val"
  CKV_ARGS+=("$flag")
  local p
  for p in "${parts[@]}"; do
    p="${p## }"; p="${p%% }"
    [[ -n "$p" ]] && CKV_ARGS+=("$p")
  done
}

# Scan target
if [ -n "$INPUT_DOCKER_IMAGE" ]; then
  add_flag --docker-image    "$INPUT_DOCKER_IMAGE"
  add_flag --dockerfile-path "$INPUT_DOCKERFILE_PATH"
elif [ -n "$INPUT_FILE" ]; then
  add_space_list -f "$INPUT_FILE"
  echo "running checkov on file: $INPUT_FILE"
else
  CKV_ARGS+=(-d "${INPUT_DIRECTORY:-.}")
  echo "running checkov on directory: ${INPUT_DIRECTORY:-.}"
fi

# Single-value flags
add_flag --output-file-path                "$INPUT_OUTPUT_FILE_PATH"
add_flag --baseline                        "$INPUT_BASELINE"
add_flag --config-file                     "$INPUT_CONFIG_FILE"
add_flag --repo-root-for-plan-enrichment   "$INPUT_REPO_ROOT_FOR_PLAN_ENRICHMENT"
add_flag --policy-metadata-filter          "$INPUT_POLICY_METADATA_FILTER"
add_flag --policy-metadata-filter-exception "$INPUT_POLICY_METADATA_FILTER_EXCEPTION"

# Boolean flags
add_bool --output-bc-ids                "$INPUT_OUTPUT_BC_IDS"
add_bool --compact                      "$INPUT_COMPACT"
add_bool --quiet                        "$INPUT_QUIET"
add_bool --soft-fail                    "$INPUT_SOFT_FAIL"
add_bool --use-enforcement-rules        "$INPUT_USE_ENFORCEMENT_RULES"
add_bool --enable-secret-scan-all-files "$INPUT_ENABLE_SECRETS_SCAN_ALL_FILES"
add_bool --skip-results-upload          "$INPUT_SKIP_RESULTS_UPLOAD"
add_bool --skip-download                "$INPUT_SKIP_DOWNLOAD"
add_bool --deep-analysis                "$INPUT_DEEP_ANALYSIS"
[[ "$INPUT_DOWNLOAD_EXTERNAL_MODULES" == "true" ]] && CKV_ARGS+=(--download-external-modules true)

# Space-separated multi-value flags (nargs='+' in checkov CLI)
add_space_list --framework      "$INPUT_FRAMEWORK"
add_space_list --skip-framework "$INPUT_SKIP_FRAMEWORK"

# Comma-separated multi-value flags (action='append' in checkov CLI)
add_csv --check               "$INPUT_CHECK"
add_csv --skip-check          "$INPUT_SKIP_CHECK"
add_csv --soft-fail-on        "$INPUT_SOFT_FAIL_ON"
add_csv --hard-fail-on        "$INPUT_HARD_FAIL_ON"
add_csv --external-checks-dir "$INPUT_EXTERNAL_CHECKS_DIRS"
add_csv --external-checks-git "$INPUT_EXTERNAL_CHECKS_REPOS"
add_csv --output              "$INPUT_OUTPUT_FORMAT"
add_csv --var-file            "$INPUT_VAR_FILE"
add_csv --skip-path           "$INPUT_SKIP_PATH"
add_csv --skip-cve-package    "$INPUT_SKIP_CVE_PACKAGE"

if [ -n "$INPUT_LOG_LEVEL" ]; then
  export LOG_LEVEL="$INPUT_LOG_LEVEL"
fi

if [[ -z "$INPUT_SOFT_FAIL" ]]; then
    echo "::add-matcher::checkov-problem-matcher.json"
else
    echo "::add-matcher::checkov-problem-matcher-softfail.json"
fi

API_KEY=${API_KEY_VARIABLE}

GIT_BRANCH=${GITHUB_HEAD_REF:="$GITHUB_REF_NAME"}
GIT_BRANCH=${GIT_BRANCH:=master}
export BC_FROM_BRANCH=${GIT_BRANCH}
export BC_TO_BRANCH=${GITHUB_BASE_REF}
export BC_PR_ID=$(echo $GITHUB_REF | awk 'BEGIN { FS = "/" } ; { print $3 }')
export BC_PR_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/pull/${BC_PR_ID}"
export BC_COMMIT_HASH=${GITHUB_SHA}
export BC_COMMIT_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/commit/${GITHUB_SHA}"
export BC_AUTHOR_NAME=${GITHUB_ACTOR}
export BC_AUTHOR_URL="${GITHUB_SERVER_URL}/${BC_AUTHOR_NAME}"
export BC_RUN_ID=${GITHUB_RUN_NUMBER}
export BC_RUN_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
export BC_REPOSITORY_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}"

echo "BC_FROM_BRANCH=${GIT_BRANCH}"
echo "BC_TO_BRANCH=${GITHUB_BASE_REF}"
echo "BC_PR_ID=$(echo $GITHUB_REF | awk 'BEGIN { FS = "/" } ; { print $3 }')"
echo "BC_PR_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/pull/${BC_PR_ID}""
echo "BC_COMMIT_HASH=${GITHUB_SHA}"
echo "BC_COMMIT_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/commit/${GITHUB_SHA}""
echo "BC_AUTHOR_NAME=${GITHUB_ACTOR}"
echo "BC_AUTHOR_URL="${GITHUB_SERVER_URL}/${BC_AUTHOR_NAME}""
echo "BC_RUN_ID=${GITHUB_RUN_NUMBER}"
echo "BC_RUN_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}""
echo "BC_REPOSITORY_URL="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}""

# Overrides all GitHub URLs with the provided PAT (needed for downloading private modules from GitHub)
# This is meant to be a last resort, if our internal mechanism doesn't work
if [ -n "$GITHUB_OVERRIDE_URL" ] && [ "$GITHUB_OVERRIDE_URL" = "true" ]; then
  git config --global url."https://x-access-token:${GITHUB_PAT}@github.com/".insteadOf "https://github.com/"
fi

if [ -n "$API_KEY_VARIABLE" ]; then
  CKV_ARGS+=(--bc-api-key "$API_KEY_VARIABLE"
             --branch "$GIT_BRANCH"
             --repo-id "$GITHUB_REPOSITORY")
fi

# Log command with API key redacted
printf 'checkov'; for a in "${CKV_ARGS[@]}"; do
  [[ "$a" == "$API_KEY_VARIABLE" && -n "$a" ]] && printf ' <API_KEY>' || printf ' %q' "$a"
done; printf '\n'

CHECKOV_RESULTS=$(checkov "${CKV_ARGS[@]}")

CHECKOV_EXIT_CODE=$?

# print to console
echo "${CHECKOV_RESULTS}"

CHECKOV_RESULTS="${CHECKOV_RESULTS//$'\\n'/''}"

# save output to GitHub files for further usage
EOF=$(dd if=/dev/urandom bs=15 count=1 status=none | base64)
{ echo "CHECKOV_RESULTS<<$EOF"; echo "${CHECKOV_RESULTS:0:65536}"; echo "$EOF"; } >> $GITHUB_ENV
{ echo "results<<$EOF"; echo "$CHECKOV_RESULTS"; echo "$EOF"; } >> $GITHUB_OUTPUT

if [ -n "$INPUT_DOWNLOAD_EXTERNAL_MODULES" ] && [ "$INPUT_DOWNLOAD_EXTERNAL_MODULES" = "true" ]; then
  echo "Cleaning up $INPUT_DIRECTORY/.external_modules directory"
  #This directory must be removed here for the self hosted github runners run as non-root user.
  rm -fr -- "${INPUT_DIRECTORY:-.}/.external_modules"
  exit $CHECKOV_EXIT_CODE
fi
exit $CHECKOV_EXIT_CODE
