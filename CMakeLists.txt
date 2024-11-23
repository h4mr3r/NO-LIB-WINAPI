cmake_minimum_required(VERSION 3.30)
project(NO-LIB-APPROACH C)

set(CMAKE_C_STANDARD 17)

include_directories(${PROJECT_SOURCE_DIR})

set(UTILTIES
        src/Utilities/string_utilities.c
        src/Utilities/string_utilities.h
)

set(CORE
        src/ApiHashing/ApiHashing.c
        src/ApiHashing/ApiHashing.h
        src/defines.h
        src/defines.c
)
add_executable(NO-LIB-APPROACH
        main.c
        src/Winblows.h
        ${CORE}
        ${UTILITIES}

)
