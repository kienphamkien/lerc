function fail() {
    echo "installation failed: $1"
    exit 1
}

function create_lerc_dirs() {
        # creates any required directories we need
    for d in \
        data \
        error_reports \
        logs
        do
                if [ ! -d "$d" ]
                then
                        echo "creating directory $d"
                        mkdir -p "$d"
                fi
        done

        return 0
}
