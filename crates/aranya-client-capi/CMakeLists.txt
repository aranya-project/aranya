option(ARANYA_ENABLE_PREVIEW "Enable preview Aranya features." OFF)
option(ARANYA_ENABLE_EXPERIMENTAL "Enable experimental Aranya features." OFF)

option(ARANYA_ENABLE_AFC "Enable Aranya Fast Channels." ON)

# ==== Daemon executable ====

corrosion_import_crate(
    MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../aranya-daemon/Cargo.toml
	FEATURES
        $<$<BOOL:${ARANYA_ENABLE_PREVIEW}>:preview>
        $<$<BOOL:${ARANYA_ENABLE_AFC}>:afc>
        $<$<BOOL:${ARANYA_ENABLE_EXPERIMENTAL}>:experimental>
    CRATES aranya-daemon
    CRATE_TYPE bin
)

add_executable(Aranya::Daemon ALIAS aranya-daemon)


# ==== Client library ====

corrosion_import_crate(
    MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
    CRATES aranya-client-capi
	FEATURES
        $<$<BOOL:${ARANYA_ENABLE_PREVIEW}>:preview>
        $<$<BOOL:${ARANYA_ENABLE_AFC}>:afc>
        $<$<BOOL:${ARANYA_ENABLE_EXPERIMENTAL}>:experimental>
)

add_custom_target(aranya_client_h
    BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/output/aranya-client.h
    COMMAND ${CMAKE_COMMAND} -E env RUSTC_BOOTSTRAP=1
        cbindgen
            --config=${CMAKE_CURRENT_SOURCE_DIR}/cbindgen.toml
            --output=${CMAKE_CURRENT_SOURCE_DIR}/output/aranya-client.h
            --verify
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Validating aranya-client.h via cbindgen"
)
add_dependencies(aranya_client_capi aranya_client_h)

target_include_directories(aranya_client_capi
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/output
)
target_compile_definitions(aranya_client_capi
    INTERFACE
        $<$<BOOL:${ARANYA_ENABLE_PREVIEW}>:ENABLE_ARANYA_PREVIEW>
        $<$<BOOL:${ARANYA_ENABLE_AFC}>:ENABLE_ARANYA_AFC>
        $<$<BOOL:${ARANYA_ENABLE_EXPERIMENTAL}>:ENABLE_ARANYA_EXPERIMENTAL>
)

add_library(Aranya::Client ALIAS aranya_client_capi)
