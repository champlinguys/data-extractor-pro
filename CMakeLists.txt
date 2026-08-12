cmake_minimum_required(VERSION 3.16)
project(DataExtractorPro VERSION 0.4.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

find_package(Qt5 COMPONENTS Widgets REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

# ---- Engine: pure C++, no Qt, unit-testable, reusable ----
add_library(de_engine STATIC
  src/core/image_source.cpp
  src/core/file_times.cpp
  src/partition/partition.cpp
  src/fs/fs_detect.cpp
  src/fs/ntfs/ntfs.cpp
  src/fs/hfs/hfs.cpp
  src/fs/apfs/apfs_container.cpp
  src/fs/apfs/apfs.cpp
  src/fs/compression/decmpfs.cpp
  src/fs/compression/lzvn.cpp
  src/fs/hfsplus/hfsplus.cpp
  src/raid/raid.cpp
  src/raid/raid_detect.cpp
  src/report/tree_report.cpp
  src/optane/imsm.cpp
  src/optane/optane_merge.cpp
  src/optane/span_map.cpp
  src/bitlocker/fve.cpp
  src/bitlocker/keys.cpp
  src/bitlocker/volume.cpp
)
target_include_directories(de_engine PUBLIC src)
target_compile_options(de_engine PRIVATE -Wall -Wextra)
target_link_libraries(de_engine PUBLIC OpenSSL::Crypto ZLIB::ZLIB)

# ---- GUI: Qt Widgets front-end ----
add_executable(data-extractor
  src/gui/main.cpp
  src/gui/main_window.cpp
  src/gui/hex_view.cpp
  src/gui/settings.cpp
  src/gui/preferences_dialog.cpp
  src/gui/device_picker.cpp
)
target_link_libraries(data-extractor PRIVATE de_engine Qt5::Widgets)

# ---- CLI: headless driver, handy for scripting/testing ----
add_executable(de-cli src/cli/main.cpp)
target_link_libraries(de-cli PRIVATE de_engine)
