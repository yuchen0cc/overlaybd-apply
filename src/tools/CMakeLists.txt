find_package(rapidjson REQUIRED)
find_package(overlaybd REQUIRED)

add_executable(overlaybd-apply overlaybd-apply.cpp)
target_include_directories(overlaybd-apply PUBLIC
    ${PHOTON_INCLUDE_DIR}
    ${OVERLAYBD_INCLUDE_DIR}
    ${rapidjson_SOURCE_DIR}/include
)
target_link_libraries(overlaybd-apply photon_static overlaybd_lib userfs_lib overlaybd_image_lib)

install(TARGETS
    overlaybd-apply
    DESTINATION /opt/overlaybd/bin
)
