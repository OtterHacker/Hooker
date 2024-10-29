cmake_minimum_required(VERSION 3.27)
project(Hooker C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_BUILD_TYPE Release)
enable_language(ASM_NASM)
SET(ASM_OPTIONS "-x assembler-with-cpp")
SET(CMAKE_ASM_FLAGS "-masm=intel ${ASM_OPTIONS}" )

set(SOURCE
        ${SOURCE}
        ${CMAKE_CURRENT_SOURCE_DIR}/hooker.c
        ${CMAKE_CURRENT_SOURCE_DIR}/main.c
        ${CMAKE_CURRENT_SOURCE_DIR}/main.c
        ${CMAKE_CURRENT_SOURCE_DIR}/pe.c
        ${CMAKE_CURRENT_SOURCE_DIR}/utils.c
        ${CMAKE_CURRENT_SOURCE_DIR}/crt.c
)

set(HEADERS
        ${HEADERS}
        ${CMAKE_CURRENT_SOURCE_DIR}/hooker.h
        ${CMAKE_CURRENT_SOURCE_DIR}/main.h
        ${CMAKE_CURRENT_SOURCE_DIR}/pe.h
        ${CMAKE_CURRENT_SOURCE_DIR}/tebpeb32.h
        ${CMAKE_CURRENT_SOURCE_DIR}/tebpeb64.h
        ${CMAKE_CURRENT_SOURCE_DIR}/utils.h
        ${CMAKE_CURRENT_SOURCE_DIR}/crt.h
)

add_executable(Hooker ${SOURCE} ${HEADERS})

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_C_FLAGS_RELEASE "")
    target_compile_options(Hooker PRIVATE $<$<COMPILE_LANGUAGE:C>:/EHs- /Zi /GS- /sdl- /MDd /Od /DNDEBUG> )
    target_link_options(Hooker PRIVATE /MANIFEST:NO /NODEFAULTLIB /ENTRY:main)
    set_target_properties(Hooker PROPERTIES LINK_FLAGS "/DEBUG:NONE")
endif()