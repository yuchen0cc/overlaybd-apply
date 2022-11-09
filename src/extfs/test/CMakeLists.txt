find_package(GTest REQUIRED)
add_executable(extfs_test test.cpp)
target_link_libraries(extfs_test photon_static extfs_lib ${GTEST_BOTH_LIBRARIES})
target_include_directories(extfs_test PUBLIC
    ${PHOTON_INCLUDE_DIR}
    ${OVERLAYBD_INCLUDE_DIR}
    ${GTEST_INCLUDE_DIR}
)
add_test(
    NAME extfs_test
    COMMAND ${EXECUTABLE_OUTPUT_PATH}/extfs_test
)

find_package(overlaybd REQUIRED)
add_executable(extfs_demo demo.cpp)
target_link_libraries(extfs_demo photon_static extfs_lib)
target_include_directories(extfs_demo PUBLIC
    ${PHOTON_INCLUDE_DIR}
    ${OVERLAYBD_INCLUDE_DIR}
)

add_executable(mkfs_test test_mkfs.cpp)
target_link_libraries(mkfs_test photon_static extfs_lib)
target_include_directories(mkfs_test PUBLIC
    ${PHOTON_INCLUDE_DIR}
    ${OVERLAYBD_INCLUDE_DIR}
)