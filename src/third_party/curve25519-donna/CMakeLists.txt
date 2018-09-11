set (SOURCES
	curve25519-donna.c
)

add_library (curve25519-donna OBJECT ${SOURCES})
set_target_properties(curve25519-donna PROPERTIES POSITION_INDEPENDENT_CODE ON)
