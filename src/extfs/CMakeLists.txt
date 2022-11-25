add_library(extfs_lib
  extfs_io.cpp
  extfs.cpp
  buffer_file.cpp
)
target_include_directories(extfs_lib PUBLIC
  ${PHOTON_INCLUDE_DIR}
  ${PROJECT_SOURCE_DIR}/deps/include
)
target_link_libraries(extfs_lib
  photon_static
  overlaybd_lib
  ext2fs
)

if(BUILD_TESTING)
  add_subdirectory(test)
endif()