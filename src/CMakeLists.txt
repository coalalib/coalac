find_library (NDM_LIB ndm)
find_library (CRYPTO_LIB crypto)

set (SOURCES
	Aead.c
	ArqBlock1Layer.c
	ArqBlock2Layer.c
	Buf.c
	CacheLayer.c
	Coala.c
	CoAPMessage.c
	Err.c
	Hkdf.c
	LayerStack.c
	LogLayer.c
	MsgCache.c
	MsgQueue.c
	ReqLayer.c
	ResLayer.c
	Sec.c
	SecLayer.c
	SlidingWindow.c
	SlidingWindowPool.c
	Str.c
	Uri.c
)

add_library (coala SHARED ${SOURCES})

add_library (coala_static STATIC ${SOURCES})
set_target_properties (coala_static PROPERTIES OUTPUT_NAME coala)

foreach (target coala coala_static)
	target_include_directories (${target}
		PUBLIC ${CMAKE_SOURCE_DIR}/include
	)

	target_link_libraries (${target}
		${CRYPTO_LIB}
		${NDM_LIB}
	)

	install (TARGETS ${target} DESTINATION lib)
endforeach (target)

install (DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION include)
