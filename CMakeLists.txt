cmake_minimum_required(VERSION 3.30)

project(yasap VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_EXPORT_COMPILE_COMMANDS on)

include(FetchContent)

# Download and set up libmem
FetchContent_Declare(libmem-config URL "https://raw.githubusercontent.com/rdbo/libmem/config-v1/libmem-config.cmake" DOWNLOAD_NO_EXTRACT TRUE)
FetchContent_MakeAvailable(libmem-config)
set(CMAKE_PREFIX_PATH "${libmem-config_SOURCE_DIR}" "${CMAKE_PREFIX_PATH}")
set(LIBMEM_DOWNLOAD_VERSION "5.0.2")

# Find libmem package
find_package(libmem CONFIG REQUIRED)

add_library(
	version
	SHARED
	main.cpp
	console.cpp
	)

target_compile_features(version PRIVATE cxx_std_20)

target_link_libraries(
	version
	PRIVATE libmem::libmem
	ntdll
	Ws2_32
)	

