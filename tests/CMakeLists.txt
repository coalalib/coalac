find_library (COAP_LIB coap-2)
find_library (CMOCKA_LIB cmocka)
find_library (NDM_LIB ndm)

# Aead
add_executable (aead Aead.c)
target_include_directories (aead PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries (aead coala)
add_test (aead aead)

# Buf
add_executable (buf Buf.c)
target_link_libraries (buf coala ${CMOCKA_LIB})
add_test (buf buf)

# CoAPMessage
add_executable (coapmessage CoAPMessage.c)
target_link_libraries (coapmessage coala ${COAP_LIB} ${CMOCKA_LIB})
add_test (coapmessage coapmessage)

# Err
add_executable (err Err.c)
target_include_directories (err PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries (err coala ${CMOCKA_LIB})
add_test (err err)

# MsgCache
add_executable (msgcache
	MsgCache.c
	${CMAKE_SOURCE_DIR}/src/Buf.c
	${CMAKE_SOURCE_DIR}/src/CoAPMessage.c
	${CMAKE_SOURCE_DIR}/src/MsgCache.c
	${CMAKE_SOURCE_DIR}/src/Str.c
	${CMAKE_SOURCE_DIR}/src/Uri.c)
target_compile_definitions (msgcache PRIVATE UNIT_TEST)
target_include_directories (msgcache PRIVATE ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src)
target_link_libraries (msgcache ${CMOCKA_LIB} ${NDM_LIB})
set_target_properties (msgcache PROPERTIES LINK_FLAGS "-Wl,--wrap=ndm_time_left_monotonic_msec")
add_test (msgcache msgcache)

# SlidingWindow
add_executable (sw SlidingWindow.c)
target_include_directories (sw PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries (sw coala ${CMOCKA_LIB})
add_test (sw sw)

# SlidingWindowPool
add_executable (swp SlidingWindowPool.c)
target_include_directories (swp PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries (swp coala ${CMOCKA_LIB})
add_test (swp swp)

# Str
add_executable (str Str.c)
target_include_directories (str PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries (str coala ${CMOCKA_LIB})
add_test (str str)

# Uri
add_executable (uri Uri.c)
target_include_directories (uri PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries (uri coala ${CMOCKA_LIB})
add_test (uri uri)
