#!/usr/bin/env bash

set -ex

export PATH="$HOME/.cargo/bin:$PATH"

OUTPUT_DIR="_site"

build_docs_install() {
    cargo install mdbook --no-default-features --features search --vers "^0.4" --locked
    cargo install mdbook-admonish --vers "^1.13" --locked
}

build_docs_build() {
    pushd docs
    mdbook-admonish install
    popd

    cat README.md | \
        sed 's#See \[the documentation\].*##' | \
        sed 's#^\*\*\(`resolved` hasn.*\)\*\*$#```admonish danger\n\1\n```#' > docs/src/README.md
    if [[ -n "${LOCAL_BUILD+x}" ]]; then
        sed -i 's#https://resolved.docs.barrucadu.co.uk/##g' docs/src/README.md
    fi
    mdbook build docs
    mv docs/book "$OUTPUT_DIR"

    cargo doc --no-deps --document-private-items --workspace
    mv target/doc "$OUTPUT_DIR/packages"
}

build_docs_fix_permissions() {
    chmod -c -R +rX "$OUTPUT_DIR" | while read -r line; do
        echo "::warning title=Invalid file permissions automatically fixed::$line"
    done
}

case "$1" in
     "install")
         build_docs_install
         ;;
     "build")
         build_docs_build
         ;;
     "fix-permissions")
         build_docs_fix_permissions
         ;;
     "")
         build_docs_install
         build_docs_build
         build_docs_fix_permissions
         ;;
esac
