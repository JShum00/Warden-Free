#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build-release"
DIST_DIR="${SCRIPT_DIR}/dist"
APPDIR="${DIST_DIR}/AppDir"
PROJECT_NAME="warden-free"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_usage() {
    cat <<EOF
Usage: ./package.sh [deb|appimage|all|clean|-h|--help]

Commands:
  deb         Configure a Release build and produce a .deb package
  appimage    Configure a Release build and produce an AppImage
  all         Build both the .deb package and AppImage
  clean       Remove release build and dist output
  -h, --help  Show this help message
EOF
}

print_status() {
    printf "%b[PACKAGE]%b %s\n" "${BLUE}" "${NC}" "$1"
}

print_progress() {
    printf "%b[PACKAGE]%b %s\n" "${YELLOW}" "${NC}" "$1"
}

print_success() {
    printf "%b[PACKAGE]%b %s\n" "${GREEN}" "${NC}" "$1"
}

print_error() {
    printf "%b[PACKAGE]%b %s\n" "${RED}" "${NC}" "$1" >&2
}

configure_release() {
    print_progress "Configuring ${PROJECT_NAME} Release build in ${BUILD_DIR}"
    cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Release
}

build_release() {
    configure_release
    print_progress "Building ${PROJECT_NAME} Release artifacts"
    cmake --build "${BUILD_DIR}" -j"$(nproc)"
}

package_deb() {
    build_release
    mkdir -p "${DIST_DIR}"
    print_progress "Generating Debian package"
    cpack --config "${BUILD_DIR}/CPackConfig.cmake" -G DEB -B "${DIST_DIR}"
    local package_path
    package_path="$(find "${DIST_DIR}" -maxdepth 1 -type f -name '*.deb' | sort | tail -n 1)"
    if [[ -z "${package_path}" ]]; then
        print_error "CPack completed but no .deb artifact was found in ${DIST_DIR}"
        exit 1
    fi

    print_success "Debian package ready: ${package_path}"
}

package_appimage() {
    build_release
    if ! command -v linuxdeployqt >/dev/null 2>&1; then
        print_error "linuxdeployqt is required for AppImage packaging. Install it and rerun './package.sh appimage'."
        exit 1
    fi

    rm -rf "${APPDIR}"
    mkdir -p "${DIST_DIR}"

    print_progress "Staging AppDir"
    cmake --install "${BUILD_DIR}" --prefix "${APPDIR}/usr"

    print_progress "Generating AppImage"
    (
        cd "${DIST_DIR}"
        linuxdeployqt "${APPDIR}/usr/share/applications/warden-free.desktop" -appimage
    )

    local appimage_path
    appimage_path="$(find "${DIST_DIR}" -maxdepth 1 -type f -name '*.AppImage' | sort | tail -n 1)"
    if [[ -z "${appimage_path}" ]]; then
        print_error "linuxdeployqt did not produce an AppImage in ${DIST_DIR}"
        exit 1
    fi

    print_success "AppImage ready: ${appimage_path}"
}

clean_outputs() {
    print_progress "Removing ${BUILD_DIR} and ${DIST_DIR}"
    rm -rf "${BUILD_DIR}" "${DIST_DIR}"
    print_success "Release outputs removed."
}

main() {
    cd "${SCRIPT_DIR}"

    if [[ $# -gt 1 ]]; then
        print_error "Too many arguments."
        print_usage
        exit 1
    fi

    case "${1:-deb}" in
        deb)
            package_deb
            ;;
        appimage)
            package_appimage
            ;;
        all)
            package_deb
            package_appimage
            ;;
        clean)
            clean_outputs
            ;;
        -h|--help)
            print_usage
            ;;
        *)
            print_error "Unrecognized argument: ${1}"
            print_usage
            exit 1
            ;;
    esac
}

main "$@"
