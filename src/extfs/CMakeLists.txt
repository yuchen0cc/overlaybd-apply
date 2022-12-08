add_library(extfs_lib
  extfs_io.cpp
  extfs.cpp
)
target_include_directories(extfs_lib PUBLIC
  ${PHOTON_INCLUDE_DIR}
)
target_link_libraries(extfs_lib
  photon_static
  overlaybd_lib
  ext2fs
)

if(BUILD_TESTING)
  add_subdirectory(test)
endif()