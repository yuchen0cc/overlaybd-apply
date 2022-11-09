add_library(mkfs_lib
  util.c
  mkfs.c
  mk_hugefiles.c
  create_inode.c
  default_profile.c
)
target_include_directories(mkfs_lib PUBLIC
  ${PROJECT_SOURCE_DIR}/deps/include
)
target_link_directories(mkfs_lib PUBLIC
  ${PROJECT_SOURCE_DIR}/deps/lib
)
target_link_libraries(mkfs_lib PUBLIC
  support blkid e2p ext2fs uuid com_err
)
