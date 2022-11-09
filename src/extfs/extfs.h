#pragma once
#include <ext2fs/ext2fs.h>
#include <photon/fs/filesystem.h>

class IOManager {
public:
    virtual io_manager get_io_manager()=0;
};

IOManager *new_io_manager(photon::fs::IFile *file);
photon::fs::IFileSystem *new_extfs(photon::fs::IFile *file);
int make_extfs(photon::fs::IFile *file,
                    const char *filepath /* with lsmt, path of file.data */,
                    size_t vsize /* virtual size (byte) */ );