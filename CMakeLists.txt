cmake_minimum_required(VERSION 3.16)
project(CryptoQtApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

# Enable automatic Qt processing
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt5 COMPONENTS Widgets REQUIRED)

# Project sources
set(PROJECT_SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/cryptoops.cpp
    include/mainwindow.h
    include/cryptoops.h
    ui/mainwindow.ui
)

# Tell AUTOUIC where to look for .ui files
set(CMAKE_AUTOUIC_SEARCH_PATHS ${CMAKE_SOURCE_DIR}/ui)

# Create the executable
add_executable(CryptoQtApp
    ${PROJECT_SOURCES}
)

# Link against Qt and Crypto++
find_library(CRYPTOPP_LIB cryptopp REQUIRED)

target_link_libraries(CryptoQtApp
    PRIVATE
        Qt5::Widgets
        ${CRYPTOPP_LIB}
)
