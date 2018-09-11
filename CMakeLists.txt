cmake_minimum_required (VERSION 2.6)
project (Coala)

include (CTest)

set (CMAKE_C_FLAGS
	"${CMAKE_C_FLAGS} -Wall -Wextra -Wno-unused-parameter -Werror")

option (WITH_SAMPLES "Build samples")
option (WITH_TESTS "Build tests")

add_subdirectory (src)

if (WITH_SAMPLES)
	add_subdirectory (examples)
endif ()

if (WITH_TESTS)
	enable_testing ()
	add_subdirectory (tests)
endif ()
