link_libraries(ext2fs)

add_library(userfs_lib
  user.cpp
)
target_include_directories(userfs_lib PUBLIC
  ${PHOTON_INCLUDE_DIR}
)

target_link_libraries(userfs_lib
  photon_static
  overlaybd_lib
)

#add_subdirectory(test)