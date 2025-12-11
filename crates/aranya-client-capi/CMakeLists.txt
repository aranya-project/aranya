# Note: Add new features as an `option` and to the `aranya_features` list.

option(ARANYA_ENABLE_PREVIEW "Enable preview Aranya features." OFF)
option(ARANYA_ENABLE_EXPERIMENTAL "Enable experimental Aranya features." OFF)

option(ARANYA_ENABLE_AFC "Enable Aranya Fast Channels." ON)


set(aranya_features preview experimental afc)

# Create lists of generator expressions used to conditionally enable features
# based on the options above. If the naming pattern becomes inconsistent,
# we'll probably just want to add the generator expressions manually.
set(crate_features)
set(header_features)
foreach(feat IN LISTS aranya_features)
    string(TOUPPER "${feat}" big_feat)
    list(APPEND crate_features $<$<BOOL:${ARANYA_ENABLE_${big_feat}}>:${feat}>)
    list(APPEND header_features $<$<BOOL:${ARANYA_ENABLE_${big_feat}}>:ENABLE_ARANYA_${big_feat}>)
endforeach()


# ==== Daemon executable ====

corrosion_import_crate(
    MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../aranya-daemon/Cargo.toml
	FEATURES ${crate_features}
    CRATES aranya-daemon
    CRATE_TYPE bin
)

add_executable(Aranya::Daemon ALIAS aranya-daemon)


# ==== Client library ====

corrosion_import_crate(
    MANIFEST_PATH ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
    CRATES aranya-client-capi
	FEATURES ${crate_features}
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
        ${header_features}
)

add_library(Aranya::Client ALIAS aranya_client_capi)

if(ARANYA_BUILD_TESTS)
    add_subdirectory(ctest)
endif()
