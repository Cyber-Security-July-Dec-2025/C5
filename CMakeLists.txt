cmake_minimum_required(VERSION 3.16)
project(CryptoQtApp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt5 COMPONENTS Widgets REQUIRED)

set(PROJECT_SOURCES
    src/main.cpp
    src/mainwindow.cpp
    src/cryptoops.cpp
    include/mainwindow.h
    include/cryptoops.h
    ui/mainwindow.ui
)

# Tell AUTOUIC where to find .ui files
set(CMAKE_AUTOUIC_SEARCH_PATHS ${CMAKE_SOURCE_DIR}/ui)

add_executable(CryptoQtApp
    ${PROJECT_SOURCES}
)

target_link_libraries(CryptoQtApp PRIVATE Qt5::Widgets)
