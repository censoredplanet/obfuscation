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
                config=*)
                    OPT="${OPTARG%%=*}"
                    export CONFIG="${OPTARG#"${OPT}="}"
                    ;;
                config)
                    export CONFIG="${!OPTIND}"
                    OPTIND=$(( OPTIND + 1 ))
                    ;;
            esac
            ;;
        h)  echo "usage: $0 --data <directory> --config <config>" ;;
        \?) exit ;;
    esac
done

# ================================================
[[ -z "${DATA_DIR}" ]] && error "--data is required"
[[ ! -e "${DATA_DIR}" ]] && error "${DATA_DIR}: No such file or directory"
[[ ! -d "${DATA_DIR}" ]] && error "${DATA_DIR}: Not a directory"

[[ -z "${CONFIG}" ]] && error "--config is required"
[[ ! -e "${CONFIG}" ]] && error "${CONFIG}: No such file or directory"
[[ ! -f "${CONFIG}" ]] && error "${CONFIG}: Not a regular file"

[[ -z "${ROOT}" ]] && error "-o is required"
# ================================================

HISTOGRAMS_SCRATCH=$(mktemp -d --tmpdir 2>/dev/null || mktemp -d -t 'tmp') || exit 1
export HISTOGRAMS_SCRATCH

export OUTPUT_DIR=${ROOT}/$(uuidgen) 
mkdir -p ${OUTPUT_DIR}

echo $0 $* > ${OUTPUT_DIR}/cmdline.txt

shopt -s nullglob
find "$DATA_DIR" -type d | while read -r DIR; do
    if find "$DIR" -mindepth 1 -type d | read; then
        continue
    fi

    ls -1 "${DIR}"/flows*.bin*
done | xargs -n 1 -P 8 bash -c '
    obfs pipeline histograms \
        --config "${CONFIG}" \
        --flows $0 \
        --output "${HISTOGRAMS_SCRATCH}/histograms.$(uuidgen).bin"
'

obfs histograms merge \
    --input ${HISTOGRAMS_SCRATCH} \
    --output ${OUTPUT_DIR}/hist.bin &

wait

ls ${HISTOGRAMS_SCRATCH}

echo "Written to ${OUTPUT_DIR}"

rm -rf ${HISTOGRAMS_SCRATCH}
