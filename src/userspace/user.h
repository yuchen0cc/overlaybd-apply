#pragma once
#include "ufs_io_mannager.h"

photon::fs::IFileSystem *new_userspace_fs(photon::fs::IFile *file);
int make_userspace_fs(photon::fs::IFile *file);