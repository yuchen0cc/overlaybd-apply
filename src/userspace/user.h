#pragma once
#include "ufs_io_mannager.h"

ext2_file_t do_ext2fs_open_file(ext2_filsys fs, const char* path, unsigned int flags, unsigned int mode);
long do_ext2fs_read(ext2_file_t file, int flags, char *buffer, unsigned long count,	unsigned long offset);
long do_ext2fs_write(ext2_file_t file, int flags, const char *buffer, unsigned long count, unsigned long offset);
errcode_t do_ext2fs_unlink(ext2_filsys fs, const char *path);
errcode_t do_ext2fs_mkdir(ext2_filsys fs, const char *path, int mode);
errcode_t do_ext2fs_rmdir(ext2_filsys fs, const char *path);
errcode_t do_ext2fs_rename(ext2_filsys fs, const char *from, const char *to);
errcode_t do_ext2fs_link(ext2_filsys fs, const char *src, const char *dest);
int do_ext2fs_symlink(ext2_filsys fs, const char *src, const char *dest);
errcode_t do_ext2fs_chmod(ext2_file_t file, int mode);
errcode_t do_ext2fs_chown(ext2_file_t file, int uid, int gid);
errcode_t do_ext2fs_mknod(ext2_filsys fs, const char *path, unsigned int st_mode, unsigned int st_rdev);

photon::fs::IFileSystem* new_userspace_fs(photon::fs::IFile *file);