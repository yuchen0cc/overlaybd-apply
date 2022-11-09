link_libraries(com_err)

add_library(userfs_lib
  extfs_io.cpp
  user.cpp
  util.c
  mkfs.c
  mk_hugefiles.c
  create_inode.c
  default_profile.c
)
target_include_directories(userfs_lib PUBLIC
  ${PHOTON_INCLUDE_DIR}
  ${PROJECT_SOURCE_DIR}/deps/include
)

target_link_libraries(userfs_lib
  photon_static
  overlaybd_lib
  ${PROJECT_SOURCE_DIR}/deps/lib/libsupport.a
  ${PROJECT_SOURCE_DIR}/deps/lib/libblkid.a
  ${PROJECT_SOURCE_DIR}/deps/lib/libe2p.a
  ${PROJECT_SOURCE_DIR}/deps/lib/libext2fs.a
  ${PROJECT_SOURCE_DIR}/deps/lib/libuuid.a
)

if(BUILD_TESTING)
  add_subdirectory(test)
endif()