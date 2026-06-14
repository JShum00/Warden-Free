#!/bin/bash
set -e

PROJECT_NAME="warden-free"
BUILD_DIR="./build"
EXECUTABLE_NAME="warden-free"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_usage() {
    echo -e "${BLUE}Usage:${NC} ./build.sh [build|run|clean|-h|--help]"
}

configure_if_needed() {
    if [ ! -f "${BUILD_DIR}/CMakeCache.txt" ]; then
        echo -e "${YELLOW}Configuring ${PROJECT_NAME}...${NC}"
        cmake -S . -B "${BUILD_DIR}" -DCMAKE_BUILD_TYPE=Debug
    fi
}

build_project() {
    configure_if_needed
    echo -e "${YELLOW}Building ${PROJECT_NAME}...${NC}"
    cmake --build "${BUILD_DIR}" -j"$(nproc)"
    echo -e "${GREEN}Build succeeded:${NC} ${BUILD_DIR}/${EXECUTABLE_NAME}"
}

run_project() {
    if [ ! -x "${BUILD_DIR}/${EXECUTABLE_NAME}" ]; then
        echo -e "${RED}Executable not found:${NC} ${BUILD_DIR}/${EXECUTABLE_NAME}"
        echo "Run ./build.sh or ./build.sh build first."
        exit 1
    fi

    echo -e "${YELLOW}Running ${PROJECT_NAME}...${NC}"
    (
        cd "${BUILD_DIR}"
        "./${EXECUTABLE_NAME}"
    )
}

case "${1:-}" in
    "")
        build_project
        run_project
        ;;
    clean)
        echo -e "${YELLOW}Cleaning ${BUILD_DIR}...${NC}"
        rm -rf "${BUILD_DIR}"
        echo -e "${GREEN}Removed:${NC} ${BUILD_DIR}"
        ;;
    build)
        build_project
        ;;
    run)
        run_project
        ;;
    -h|--help)
        print_usage
        ;;
    *)
        echo -e "${RED}Unrecognized argument:${NC} $1"
        print_usage
        exit 1
        ;;
esac
