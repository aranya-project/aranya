get_filename_component(dir ${CMAKE_CURRENT_LIST_DIR} DIRECTORY)

set(lib "${dir}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}aranya_client${CMAKE_SHARED_LIBRARY_SUFFIX}")

add_library(Aranya::Aranya IMPORTED SHARED)
set_target_properties(Aranya::Aranya PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${dir}/include"
    IMPORTED_LOCATION "${lib}"
    IMPORTED_IMPLIB "${lib}")

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    set_target_properties(Aranya::Aranya PROPERTIES IMPORTED_NO_SONAME TRUE)
elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    set_target_properties(Aranya::Aranya PROPERTIES IMPORTED_SONAME "@rpath/libaranya_client.dylib")
endif()
