include(FetchContent)
set(FETCHCONTENT_QUIET false)

FetchContent_Declare(
  overlaybd
  GIT_REPOSITORY https://github.com/containerd/overlaybd.git
  GIT_TAG main
)

if(BUILD_TESTING)
  set(BUILD_TESTING 0)
  FetchContent_MakeAvailable(overlaybd)
  set(BUILD_TESTING 1)
else()
  FetchContent_MakeAvailable(overlaybd)
endif()
set(OVERLAYBD_INCLUDE_DIR ${overlaybd_SOURCE_DIR}/src)
