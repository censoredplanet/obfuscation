#!/usr/bin/env bash

error() {
    echo "$0: $*" >&2
    exit 1
}

while getopts "o:h-:" OPT ; do
    case "${OPT}" in
        o)
            export ROOT=${OPTARG}
            mkdir -p ${ROOT}
            ;;
        -) 
            case ${OPTARG} in
                data=*)
                    OPT="${OPTARG%%=*}"
                    DATA_DIR="${OPTARG#"${OPT}="}" 
                    echo ${DATA_DIR}
                    ;;
                data) 
                    DATA_DIR="${!OPTIND}"
                    OPTIND=$(( OPTIND + 1 ))
                    ;;
                markov-order=*)
                    OPT="${OPTARG%%=*}"
                    MARKOV_ORDER="${OPTARG#"${OPT}="}"
                    ;;
                markov-order)
                    MARKOV_ORDER="${!OPTIND}"
                    OPTIND=$(( OPTIND + 1 ))
                    ;;
                stats-out=*)
                    OPT="${OPTARG%%=*}"
                    STATS_OUT="${OPTARG#"${OPT}="}"
                    ;;
                stats-out)
                    STATS_OUT="${!OPTIND}"
                    OPTIND=$(( OPTIND + 1 ))
                    ;;
                assumptions-out=*)
                    OPT="${OPTARG%%=*}"
                    MODEL_ASSUMPTIONS_OUT="${OPTARG#"${OPT}="}"
                    ;;
                assumptions-out)
                    MODEL_ASSUMPTIONS_OUT="${!OPTIND}"
                    OPTIND=$(( OPTIND + 1 ))
                    ;;
                epsilon=*)
                    OPT="${OPTARG%%=*}"
                    EPSILON="--epsilon ${OPTARG#"${OPT}="}"
                    ;;
                epsilon)
                    EPSILON="--epsilon ${!OPTIND}"
                    OPTIND=$(( OPTIND + 1 ))
                    ;;
                delta=*)
                    OPT="${OPTARG%%=*}"
                    DELTA="--delta ${OPTARG#"${OPT}="}"
                    ;;
                delta)
                    DELTA="--delta ${!OPTIND}"
                    OPTIND=$(( OPTIND + 1 ))
                    ;;
            esac
            ;;
        h)  echo "usage: $0 --data <directory> --markov-order <markov-order> --stats-out <stats-out> --assumptions-out <assumptions-out>" ;;
        \?) exit ;;
    esac
done

# =====
[[ -z "${DATA_DIR}" ]] && error "--data is required"
[[ ! -e "${DATA_DIR}" ]] && error "${DATA_DIR}: No such file or directory"
[[ ! -d "${DATA_DIR}" ]] && error "${DATA_DIR}: Not a directory"

[[ -z "${MARKOV_ORDER}" ]] && error "--markov-order is required"
[[ -z "${STATS_OUT}" ]] && error "--stats-out is required"
[[ -z "${MODEL_ASSUMPTIONS_OUT}" ]] && error "--assumptions-out is required"
# =====

export TMPDIR
export STATS_SCRATCH=$(mktemp -d --tmpdir 2>/dev/null || mktemp -d -t 'tmp') || exit 1

find "${DATA_DIR}" -type d | while read -r DIR; do
    if find "$DIR" -mindepth 1 -type d | read; then
        continue
    fi

    shopt -s nullglob
    ls -1 "${DIR}"/flows*.bin*
done | xargs -n 1 -P 8 bash -c '
    obfs stats compute \
        --flows "$0" \
        --output "${STATS_SCRATCH}/stats.$(uuidgen).bin" \
        --strip-tls-handshake
'

ls "$STATS_SCRATCH"

obfs stats merge --input "$STATS_SCRATCH" --output ${STATS_OUT}

obfs stats bin \
    --input ${STATS_OUT} \
    --output ${MODEL_ASSUMPTIONS_OUT} \
    --markov-order ${MARKOV_ORDER} \
    ${EPSILON[@]} \
    ${DELTA[@]}
    
rm -rf "$STATS_SCRATCH"
