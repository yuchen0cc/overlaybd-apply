add_subdirectory(mkfs)

add_library(extfs_lib
  extfs_io.cpp
  extfs.cpp
)
target_include_directories(extfs_lib PUBLIC
  ${PHOTON_INCLUDE_DIR}
  ${PROJECT_SOURCE_DIR}/deps/include
)
target_link_libraries(extfs_lib
  photon_static
  overlaybd_lib
  mkfs_lib
)

if(BUILD_TESTING)
  add_subdirectory(test)
endif()