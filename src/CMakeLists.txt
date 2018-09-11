find_library (NDM_LIB ndm)
find_library (CRYPTO_LIB crypto)
find_package (Threads)

set (SOURCES
	Aead.c
	ArqBlock1Layer.c
	ArqBlock2Layer.c
	Buf.c
	Coala.c
	CoAPMessage.c
	CoAPMessagePool.c
	Err.c
	HexString.c
	LayerStack.c
	LogLayer.c
	Mem.c
	RequestLayer.c
	ResponseLayer.c
	SecurityLayer.c
	SlidingWindow.c
	SlidingWindowPool.c
	Sin.c
	Str.c
	TimeMono.c
	Uri.c
)

add_library (coala SHARED
	${SOURCES}
	$<TARGET_OBJECTS:curve25519-donna>
)

target_include_directories (coala
	PUBLIC ${CMAKE_SOURCE_DIR}/include
	PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/curve25519-donna
)

target_link_libraries (coala
	${CMAKE_THREAD_LIBS_INIT}
	${CRYPTO_LIB}
	${NDM_LIB}
)

install (TARGETS coala DESTINATION lib)
install (DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION include)

add_subdirectory (third_party)
