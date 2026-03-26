#!/usr/bin/env bash

if [[ $# -ne 1 ]] ; then
    echo "usage: $0 <data_directory>"
    exit 1
fi

DATA_DIR=$1

find "${DATA_DIR}" -type d | while read -r DIR; do
    if find "${DIR}" -mindepth 1 -type d | read; then
        continue
    fi

    shopt -s nullglob

    FLOW_LOGS=( "${DIR}"/obfuscation*.log* )
    PKT_LOGS=( "${DIR}"/packets*.log* )

    [[ ${#FLOW_LOGS[@]} -ne 1 ]] && continue
    [[ ${#PKT_LOGS[@]} -ne 1 ]] && continue

    FLOW_LOG="${FLOW_LOGS[0]}"
    PKT_LOG="${PKT_LOGS[0]}"

    echo "$DIR" "$FLOW_LOG" "$PKT_LOG"
done | xargs -n 3 -P 8 bash -c '
    DIR="$0"
    FLOW_LOG="$1"
    PKT_LOG="$2"

    obfs zeek2flows \
        --flows "${FLOW_LOG}" \
        --packets "${PKT_LOG}" \
        --output "${DIR}/flows.bin"
'
