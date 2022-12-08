#pragma once
#include <ext2fs/ext2fs.h>
#include <photon/fs/filesystem.h>

#define DEFAULT_BLOCK_SIZE 4096

class IOManager {
public:
    virtual io_manager get_io_manager()=0;
    virtual ~IOManager() {}
};

IOManager *new_io_manager(photon::fs::IFile *file);
photon::fs::IFileSystem *new_extfs(photon::fs::IFile *file, bool buffer = true);