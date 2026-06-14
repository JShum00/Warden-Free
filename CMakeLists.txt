cmake_minimum_required(VERSION 3.16)

project(WardenFree VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Concurrent Core Widgets)
find_package(OpenSSL REQUIRED)
find_path(CLAMAV_INCLUDE_DIR NAMES clamav.h REQUIRED)
find_library(CLAMAV_LIBRARY NAMES clamav REQUIRED)
find_library(FRESHCLAM_LIBRARY NAMES freshclam)

set(WARDEN_FREE_COMMON_SOURCES
    src/scanner/ClamAvScanner.cpp
    src/scanner/ClamAvOnlyCoordinator.cpp
    src/scanner/FileWalker.cpp
    src/scanner/QuarantineManager.cpp
    src/scanner/Sha256Hasher.cpp
    src/network/DefinitionUpdater.cpp
    src/bridge/ClamAvBridgeService.cpp
    headers/warden/bridge/ClamAvBridgeProtocol.h
    headers/warden/bridge/ClamAvBridgeService.h
    headers/warden/core/ScanTypes.h
    headers/warden/network/DefinitionUpdater.h
    headers/warden/scanner/ClamAvOnlyCoordinator.h
    headers/warden/scanner/ClamAvScanner.h
    headers/warden/scanner/FileWalker.h
    headers/warden/scanner/QuarantineManager.h
    headers/warden/scanner/Sha256Hasher.h
)

add_executable(warden-free
    src/main.cpp
    src/MainWindow.cpp
    resources/warden_resources.qrc
    ${WARDEN_FREE_COMMON_SOURCES}
    headers/MainWindow.h
)

if(WIN32)
    target_sources(warden-free PRIVATE packaging/windows/warden-free.rc)
endif()

add_executable(warden-clamav-bridge
    src/bridge/main_bridge.cpp
    ${WARDEN_FREE_COMMON_SOURCES}
)

foreach(target warden-free warden-clamav-bridge)
    target_include_directories(${target}
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/headers
            ${CLAMAV_INCLUDE_DIR}
    )
    target_link_libraries(${target}
        PRIVATE
            Qt6::Concurrent
            Qt6::Core
            Qt6::Widgets
            OpenSSL::Crypto
            ${CLAMAV_LIBRARY}
    )
    if(FRESHCLAM_LIBRARY)
        target_compile_definitions(${target} PRIVATE WARDEN_HAS_FRESHCLAM=1)
        target_link_libraries(${target} PRIVATE ${FRESHCLAM_LIBRARY})
    endif()
endforeach()

install(TARGETS warden-free warden-clamav-bridge
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

if(UNIX AND NOT APPLE)
    install(FILES packaging/linux/warden-free.desktop
        DESTINATION ${CMAKE_INSTALL_DATADIR}/applications
    )
    install(FILES assets/Warden-Logo-Transparent.png
        DESTINATION ${CMAKE_INSTALL_DATADIR}/icons/hicolor/256x256/apps
        RENAME warden-free.png
    )
endif()

install(FILES README.md LICENSE
    DESTINATION ${CMAKE_INSTALL_DOCDIR}/warden-free
)

set(CPACK_PACKAGE_NAME "warden-free")
set(CPACK_PACKAGE_VENDOR "WardenAV")
set(CPACK_PACKAGE_CONTACT "WardenAV")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Warden Free ClamAV-powered filesystem scanner")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_PACKAGE_EXECUTABLES "warden-free;Warden Free")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "WardenAV")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "clamav-freshclam")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

include(CPack)
