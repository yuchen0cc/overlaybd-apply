add_executable(ufs_test test.cpp)
target_link_libraries(ufs_test photon_static userfs_lib)
target_include_directories(ufs_test PUBLIC
    ${PHOTON_INCLUDE_DIR}
    ${OVERLAYBD_INCLUDE_DIR}
)

find_package(overlaybd REQUIRED)
add_executable(ufs_test_2 test2.cpp)
target_link_libraries(ufs_test_2 photon_static userfs_lib)
target_include_directories(ufs_test_2 PUBLIC
    ${PHOTON_INCLUDE_DIR}
    ${OVERLAYBD_INCLUDE_DIR}
)