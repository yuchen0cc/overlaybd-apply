#include "extfs.h"
#include <utime.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string>
#include <sstream>
#include <sys/types.h>
#include <unistd.h>
#include <vector>
#include <sys/sysmacros.h>

#include <photon/photon.h>
#include <photon/common/alog.h>
#include <photon/common/alog-stdstring.h>
#include <photon/fs/filesystem.h>
#include <photon/fs/localfs.h>
#include <photon/fs/aligned-file.h>

#include "extfs_utils.h"

ext2_filsys do_ext2fs_open(io_manager extfs_manager) {
    ext2_filsys fs;
    errcode_t ret = ext2fs_open(
        "lsmt-image",
        EXT2_FLAG_RW,         // flags
        0,                    // superblock
        DEFAULT_BLOCK_SIZE,   // block_size
        extfs_manager,        // io manager
        &fs                   // ret_fs
    );
    if (ret) {
        errno = -translate_error(nullptr, 0, ret);
        LOG_ERROR("failed ext2fs_open, errno `:`", errno, strerror(errno));
        return nullptr;
    }
    ret = ext2fs_read_bitmaps(fs);
    if (ret) {
        errno = -translate_error(fs, 0, ret);
        LOG_ERROR("failed ext2fs_read_bitmaps, errno `:`", errno, strerror(errno));
        ext2fs_close(fs);
        return nullptr;
    }
    return fs;
}

ext2_file_t do_ext2fs_open_file(ext2_filsys fs, const char *path, unsigned int flags, unsigned int mode) {
    ext2_ino_t ino = string_to_inode(fs, path, !(flags & O_NOFOLLOW));
    LOG_DEBUG(VALUE(path), VALUE(ino));
    errcode_t ret;
    if (ino == 0) {
        if (!(flags & O_CREAT)) {
            errno = ENOENT;
            return nullptr;
        }
        ret = create_file(fs, path, mode, &ino);
        if (ret) {
            errno = -ret;
            LOG_ERROR("failed to create file ", VALUE(ret), VALUE(path));
            return nullptr;
        }
    } else if (flags & O_EXCL) {
        errno = EEXIST;
        return nullptr;
    }
    if ((flags & O_DIRECTORY) && ext2fs_check_directory(fs, ino)) {
        errno = ENOTDIR;
        return nullptr;
    }
    ext2_file_t file;
    ret = ext2fs_file_open(fs, ino, translate_open_flags(flags), &file);
    if (ret) {
        errno = -translate_error(fs, ino, ret);
        return nullptr;
    }
    if (flags & O_TRUNC) {
        ret = ext2fs_file_set_size2(file, 0);
        if (ret) {
            errno = -translate_error(fs, ino, ret);
            return nullptr;
        }
    }
    return file;
}

long do_ext2fs_read(
    ext2_file_t file,
    int flags,
    char *buffer,
    size_t count,  // requested count
    off_t offset  // offset in file, -1 for current offset
) {
    errcode_t ret = 0;
    if ((flags & O_WRONLY) != 0) {
        // Don't try to read write only files.
        return -EBADF;
    }
    if (offset != -1) {
        ret = ext2fs_file_llseek(file, offset, EXT2_SEEK_SET, NULL);
        if (ret) return translate_error(nullptr, 0, ret);
    }
    unsigned int got;
    ret = ext2fs_file_read(file, buffer, count, &got);
    if (ret) return translate_error(nullptr, 0, ret);
    if ((flags & O_NOATIME) == 0) {
        ret = update_xtime(file, true, false, false);
        if (ret) return ret;
    }
    return got;
}

long do_ext2fs_write(
    ext2_file_t file,
    int flags,
    const char *buffer,
    size_t count,  // requested count
    off_t offset  // offset in file, -1 for current offset
) {
    if ((flags & (O_WRONLY | O_RDWR)) == 0) {
        // Don't try to write to readonly files.
        return -EBADF;
    }
    errcode_t ret = 0;
    if ((flags & O_APPEND) != 0) {
        // append mode: seek to the end before each write
        ret = ext2fs_file_llseek(file, 0, EXT2_SEEK_END, NULL);
    } else if (offset != -1) {
        ret = ext2fs_file_llseek(file, offset, EXT2_SEEK_SET, NULL);
    }

    if (ret) return translate_error(nullptr, 0, ret);
    unsigned int written;
    ret = ext2fs_file_write(file, buffer, count, &written);
    if (ret) return translate_error(nullptr, 0, ret);
    ret = update_xtime(file, false, true, true);
    if (ret) return ret;

    ret = ext2fs_file_flush(file);
    if (ret) {
        return translate_error(nullptr, 0, ret);
    }

    return written;
}

int do_ext2fs_chmod(ext2_file_t file, int mode) {
    ext2_filsys fs = ext2fs_file_get_fs(file);
    ext2_ino_t ino = ext2fs_file_get_inode_num(file);
    ext2_inode *inode = ext2fs_file_get_inode(file);
    errcode_t ret = ext2fs_read_inode(fs, ino, inode);
    if (ret) return translate_error(fs, ino, ret);
    // keep only fmt (file or directory)
    inode->i_mode &= LINUX_S_IFMT;
    // apply new mode
    inode->i_mode |= (mode & ~LINUX_S_IFMT);
    increment_version(inode);
    ret = ext2fs_write_inode(fs, ino, inode);
    if (ret) return translate_error(fs, ino, ret);
    return 0;
}

int do_ext2fs_chown(ext2_file_t file, int uid, int gid) {
    ext2_filsys fs = ext2fs_file_get_fs(file);
    ext2_ino_t ino = ext2fs_file_get_inode_num(file);
    ext2_inode *inode = ext2fs_file_get_inode(file);
    // TODO handle 32 bit {u,g}ids
    errcode_t ret = ext2fs_read_inode(fs, ino, inode);
    if (ret) return translate_error(fs, ino, ret);
    // keep only the lower 16 bits
    inode->i_uid = uid & 0xFFFF;
    ext2fs_set_i_uid_high(*inode, uid >> 16);
    inode->i_gid = gid & 0xFFFF;
    ext2fs_set_i_gid_high(*inode, gid >> 16);
    increment_version(inode);
    ret = ext2fs_write_inode(fs, ino, inode);
    if (ret) return translate_error(fs, ino, ret);
    return 0;
}

int do_ext2fs_utimes(ext2_file_t file, const struct timeval tv[2]) {
    int ret = 0;
    timespec tm{};
    tm = {tv[0].tv_sec, tv[0].tv_usec * 1000};
    ret = update_xtime(file, true, false, false, &tm);
    if (ret) return ret;
    tm = {tv[1].tv_sec, tv[1].tv_usec * 1000};
    ret = update_xtime(file, false, false, true, &tm);
    if (ret) return ret;
    ret = update_xtime(file, false, true, false);
    if (ret) return ret;
    return 0;
}

int do_ext2fs_unlink(ext2_filsys fs, const char *path) {
    ext2_ino_t ino;
    errcode_t ret = 0;

    ret = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &ino);
    if (ret) return translate_error(fs, 0, ret);

    if (ext2fs_check_directory(fs, ino) == 0) {
        return -EISDIR;
    }

    ret = unlink_file_by_name(fs, path);
    if (ret) return ret;

    ret = remove_inode(fs, ino);
    if (ret) return ret;

    return 0;
}

int do_ext2fs_mkdir(ext2_filsys fs, const char *path, int mode) {
    ext2_ino_t parent_ino = get_parent_dir_ino(fs, path);
    LOG_DEBUG(VALUE(path), VALUE(mode), VALUE(parent_ino));
    if (parent_ino == 0) {
        return -ENOTDIR;
    }
    char *filename = get_filename(path);
    if (filename == nullptr) {
        // This should never happen.
        return -EISDIR;
    }
    ext2_ino_t newdir;
    errcode_t ret = 0;
    ret = ext2fs_new_inode(
        fs,
        parent_ino,
        LINUX_S_IFDIR,
        NULL,
        &newdir);
    if (ret) return translate_error(fs, 0, ret);
    ret = ext2fs_mkdir(fs, parent_ino, newdir, filename);
    LOG_DEBUG("ext2fs_mkdir ", VALUE(filename), VALUE(newdir), VALUE(ret));
    if (ret) return translate_error(fs, 0, ret);
    struct ext2_inode inode;
    ret = ext2fs_read_inode(fs, newdir, &inode);
    if (ret) return translate_error(fs, 0, ret);
    inode.i_mode = (mode & ~LINUX_S_IFMT) | LINUX_S_IFDIR;
    ret = ext2fs_write_inode(fs, newdir, &inode);
    if (ret) return translate_error(fs, 0, ret);
    return 0;
}

int do_ext2fs_rmdir(ext2_filsys fs, const char *path) {
    ext2_ino_t child;
    errcode_t ret = 0;
    struct ext2_inode_large inode;
    struct rd_struct rds;

    ret = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, path, &child);
    if (ret) return translate_error(fs, 0, ret);

    LOG_DEBUG("rmdir path=` ino=`", path, child);

    rds.parent = 0;
    rds.empty = 1;

    ret = ext2fs_dir_iterate2(fs, child, 0, 0, rmdir_proc, &rds);
    if (ret) return translate_error(fs, child, ret);

    if (rds.empty == 0) return -ENOTEMPTY;

    ret = unlink_file_by_name(fs, path);
    if (ret) return ret;
    /* Directories have to be "removed" twice. */
    ret = remove_inode(fs, child);
    if (ret) return ret;
    ret = remove_inode(fs, child);
    if (ret) return ret;

    if (rds.parent) {
        LOG_DEBUG("decr dir=` link count", rds.parent);
        ret = ext2fs_read_inode_full(fs, rds.parent, (struct ext2_inode *)&inode, sizeof(inode));
        if (ret) return translate_error(fs, rds.parent, ret);

        if (inode.i_links_count > 1)
            inode.i_links_count--;
        ret = update_mtime(fs, rds.parent, &inode);
        if (ret) return ret;
        ret = ext2fs_write_inode_full(fs, rds.parent, (struct ext2_inode *)&inode, sizeof(inode));
        if (ret) return translate_error(fs, rds.parent, ret);
    }

    return 0;
}

int do_ext2fs_rename(ext2_filsys fs, const char *from, const char *to) {
    errcode_t ret = 0;
    ext2_ino_t from_ino, to_ino, to_dir_ino, from_dir_ino;
    char *temp_to = NULL, *temp_from = NULL;
    char *cp, a;
    struct ext2_inode inode;
    struct update_dotdot ud;

    LOG_DEBUG("renaming ` to `", from, to);

    ret = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, from, &from_ino);
    if (ret || from_ino == 0)
        return translate_error(fs, 0, ret);

    ret = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, to, &to_ino);
    if (ret && ret != EXT2_ET_FILE_NOT_FOUND)
        return translate_error(fs, 0, ret);

    if (ret == EXT2_ET_FILE_NOT_FOUND)
        to_ino = 0;

    /* Already the same file? */
    if (to_ino != 0 && to_ino == from_ino)
        return 0;

    temp_to = strdup(to);
    if (!temp_to) return -ENOMEM;
    DEFER(free(temp_to););
    temp_from = strdup(from);
    if (!temp_from) return -ENOMEM;
    DEFER(free(temp_from););

    /* Find parent dir of the source and check write access */
    cp = strrchr(temp_from, '/');
    if (!cp) return -EINVAL;

    a = *(cp + 1);
    *(cp + 1) = 0;
    ret = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_from, &from_dir_ino);
    *(cp + 1) = a;
    if (ret) return translate_error(fs, 0, ret);
    if (from_dir_ino == 0) return -ENOENT;

    /* Find parent dir of the destination and check write access */
    cp = strrchr(temp_to, '/');
    if (!cp) return -EINVAL;

    a = *(cp + 1);
    *(cp + 1) = 0;
    ret = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_to, &to_dir_ino);
    *(cp + 1) = a;
    if (ret) return translate_error(fs, 0, ret);
    if (to_dir_ino == 0) return -ENOENT;

    /* If the target exists, unlink it first */
    if (to_ino != 0) {
        ret = ext2fs_read_inode(fs, to_ino, &inode);
        if (ret) return translate_error(fs, to_ino, ret);

        LOG_DEBUG("unlinking ` ino=`", LINUX_S_ISDIR(inode.i_mode) ? "dir" : "file", to_ino);
        if (LINUX_S_ISDIR(inode.i_mode))
            ret = do_ext2fs_rmdir(fs, to);
        else
            ret = do_ext2fs_unlink(fs, to);
        if (ret) return ret;
    }

    /* Get ready to do the move */
    ret = ext2fs_read_inode(fs, from_ino, &inode);
    if (ret) return translate_error(fs, from_ino, ret);

    /* Link in the new file */
    LOG_DEBUG("linking ino=`/path=` to dir=`", from_ino, cp + 1, to_dir_ino);
    ret = ext2fs_link(fs, to_dir_ino, cp + 1, from_ino, ext2_file_type(inode.i_mode));
    if (ret == EXT2_ET_DIR_NO_SPACE) {
        ret = ext2fs_expand_dir(fs, to_dir_ino);
        if (ret) return translate_error(fs, to_dir_ino, ret);

        ret = ext2fs_link(fs, to_dir_ino, cp + 1, from_ino, ext2_file_type(inode.i_mode));
    }
    if (ret) return translate_error(fs, to_dir_ino, ret);

    /* Update '..' pointer if dir */
    ret = ext2fs_read_inode(fs, from_ino, &inode);
    if (ret) return translate_error(fs, from_ino, ret);

    if (LINUX_S_ISDIR(inode.i_mode)) {
        ud.new_dotdot = to_dir_ino;
        LOG_DEBUG("updating .. entry for dir=`", to_dir_ino);
        ret = ext2fs_dir_iterate2(fs, from_ino, 0, NULL, update_dotdot_helper, &ud);
        if (ret) return translate_error(fs, from_ino, ret);

        /* Decrease from_dir_ino's links_count */
        LOG_DEBUG("moving linkcount from dir=` to dir=`", from_dir_ino, to_dir_ino);
        ret = ext2fs_read_inode(fs, from_dir_ino, &inode);
        if (ret) return translate_error(fs, from_dir_ino, ret);
        inode.i_links_count--;
        ret = ext2fs_write_inode(fs, from_dir_ino, &inode);
        if (ret) return translate_error(fs, from_dir_ino, ret);

        /* Increase to_dir_ino's links_count */
        ret = ext2fs_read_inode(fs, to_dir_ino, &inode);
        if (ret) return translate_error(fs, to_dir_ino, ret);
        inode.i_links_count++;
        ret = ext2fs_write_inode(fs, to_dir_ino, &inode);
        if (ret) return translate_error(fs, to_dir_ino, ret);
    }

    /* Update timestamps */
    ret = update_ctime(fs, from_ino, nullptr);
    if (ret) return ret;

    ret = update_mtime(fs, to_dir_ino, nullptr);
    if (ret) return ret;

    /* Remove the old file */
    ret = unlink_file_by_name(fs, from);
    if (ret) return ret;

    /* Flush the whole mess out */
    ret = ext2fs_flush2(fs, 0);
    if (ret) return translate_error(fs, 0, ret);

    return 0;
}

int do_ext2fs_link(ext2_filsys fs, const char *src, const char *dest) {
    char *temp_path;
    errcode_t ret = 0;
    char *node_name, a;
    ext2_ino_t parent, ino;
    struct ext2_inode_large inode;

    LOG_DEBUG(VALUE(src), VALUE(dest));
    temp_path = strdup(dest);
    if (!temp_path) return -ENOMEM;
    DEFER(free(temp_path););
    node_name = strrchr(temp_path, '/');
    if (!node_name) return -ENOMEM;
    node_name++;
    a = *node_name;
    *node_name = 0;

    ret = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path, &parent);
    *node_name = a;
    if (ret) return -ENOENT;

    ret = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, src, &ino);
    if (ret || ino == 0) return translate_error(fs, 0, ret);

    memset(&inode, 0, sizeof(inode));
    ret = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode, sizeof(inode));
    if (ret) return translate_error(fs, ino, ret);

    inode.i_links_count++;
    ret = update_ctime(fs, ino, &inode);
    if (ret) return ret;

    ret = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode, sizeof(inode));
    if (ret) return translate_error(fs, ino, ret);

    LOG_DEBUG("linking ino=`/name=` to dir=`", ino, node_name, parent);
    ret = ext2fs_link(fs, parent, node_name, ino, ext2_file_type(inode.i_mode));
    if (ret == EXT2_ET_DIR_NO_SPACE) {
        ret = ext2fs_expand_dir(fs, parent);
        if (ret) return translate_error(fs, parent, ret);

        ret = ext2fs_link(fs, parent, node_name, ino, ext2_file_type(inode.i_mode));
    }
    if (ret) return translate_error(fs, parent, ret);

    ret = update_mtime(fs, parent, NULL);
    if (ret) return ret;

    return 0;
}

int do_ext2fs_symlink(ext2_filsys fs, const char *src, const char *dest) {
    ext2_ino_t parent, child;
    char *temp_path;
    errcode_t ret = 0;
    char *node_name, a;
    struct ext2_inode_large inode;

    LOG_DEBUG(VALUE(src), VALUE(dest));
    temp_path = strdup(dest);
    if (!temp_path) return -ENOMEM;
    DEFER(free(temp_path););
    node_name = strrchr(temp_path, '/');
    if (!node_name) return -ENOMEM;
    node_name++;
    a = *node_name;
    *node_name = 0;

    ret = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path, &parent);
    *node_name = a;
    if (ret) return translate_error(fs, 0, ret);
    LOG_DEBUG(VALUE(parent));

    /* Create symlink */
    ret = ext2fs_symlink(fs, parent, 0, node_name, src);
    if (ret == EXT2_ET_DIR_NO_SPACE) {
        ret = ext2fs_expand_dir(fs, parent);
        if (ret) return translate_error(fs, parent, ret);

        ret = ext2fs_symlink(fs, parent, 0, node_name, src);
    }
    if (ret) return translate_error(fs, parent, ret);

    /* Update parent dir's mtime */
    ret = update_mtime(fs, parent, NULL);
    if (ret) return ret;

    /* Still have to update the uid/gid of the symlink */
    ret = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO, temp_path, &child);
    if (ret) return translate_error(fs, 0, ret);

    LOG_DEBUG("symlinking ino=`/name=` to dir=`", child, node_name, parent);
    memset(&inode, 0, sizeof(inode));
    ret = ext2fs_read_inode_full(fs, child, (struct ext2_inode *)&inode, sizeof(inode));
    if (ret) return translate_error(fs, child, ret);

    ret = ext2fs_write_inode_full(fs, child, (struct ext2_inode *)&inode, sizeof(inode));
    if (ret) return translate_error(fs, child, ret);

    return 0;
}

int do_ext2fs_mknod(ext2_filsys fs, const char *path, unsigned int st_mode, unsigned int st_rdev) {
    ext2_ino_t ino;
    errcode_t ret = 0;
    struct ext2_inode inode;
    unsigned long devmajor, devminor;
    int filetype;

    ino = string_to_inode(fs, path, 0);
    if (ino) return -EEXIST;

    ext2_ino_t parent_ino = get_parent_dir_ino(fs, path);
    if (parent_ino == 0) return -ENOTDIR;

    char *filename = get_filename(path);
    if (filename == nullptr) return -EISDIR;

    switch (st_mode & S_IFMT) {
        case S_IFCHR:
            filetype = EXT2_FT_CHRDEV;
            break;
        case S_IFBLK:
            filetype = EXT2_FT_BLKDEV;
            break;
        case S_IFIFO:
            filetype = EXT2_FT_FIFO;
            break;
#ifndef _WIN32
        case S_IFSOCK:
            filetype = EXT2_FT_SOCK;
            break;
#endif
        default:
            return EXT2_ET_INVALID_ARGUMENT;
    }

    ret = ext2fs_new_inode(fs, parent_ino, 010755, 0, &ino);
    if (ret) return translate_error(fs, 0, ret);
    LOG_DEBUG(VALUE(ino));

    ret = ext2fs_link(fs, parent_ino, filename, ino, filetype);
    if (ret == EXT2_ET_DIR_NO_SPACE) {
        ret = ext2fs_expand_dir(fs, parent_ino);
        if (ret) return translate_error(fs, parent_ino, ret);

        ret = ext2fs_link(fs, parent_ino, filename, ino, filetype);
    }
    if (ret) return translate_error(fs, parent_ino, ret);

    if (ext2fs_test_inode_bitmap2(fs->inode_map, ino))
        LOG_WARN("Warning: inode already set");
    ext2fs_inode_alloc_stats2(fs, ino, +1, 0);
    memset(&inode, 0, sizeof(inode));
    inode.i_mode = st_mode;
    inode.i_atime = inode.i_ctime = inode.i_mtime =
        fs->now ? fs->now : time(0);

    if (filetype != S_IFIFO) {
        devmajor = major(st_rdev);
        devminor = minor(st_rdev);

        if ((devmajor < 256) && (devminor < 256)) {
            inode.i_block[0] = devmajor * 256 + devminor;
            inode.i_block[1] = 0;
        } else {
            inode.i_block[0] = 0;
            inode.i_block[1] = (devminor & 0xff) | (devmajor << 8) |
                               ((devminor & ~0xff) << 12);
        }
    }
    inode.i_links_count = 1;

    ret = ext2fs_write_new_inode(fs, ino, &inode);
    if (ret) return translate_error(fs, ino, ret);

    return 0;
}

int do_ext2fs_stat(ext2_filsys fs, const char *path, struct stat *statbuf, int follow) {
    ext2_ino_t ino = string_to_inode(fs, path, follow);
    if (!ino) return -ENOENT;

    struct ext2_inode_large inode;
    dev_t fakedev = 0;
    errcode_t ret;
    struct timespec tv;

    memset(&inode, 0, sizeof(inode));
    ret = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode, sizeof(inode));
    if (ret) return translate_error(fs, ino, ret);

    memcpy(&fakedev, fs->super->s_uuid, sizeof(fakedev));
    statbuf->st_dev = fakedev;
    statbuf->st_ino = ino;
    statbuf->st_mode = inode.i_mode;
    statbuf->st_nlink = inode.i_links_count;
    statbuf->st_uid = inode_uid(inode);
    statbuf->st_gid = inode_gid(inode);
    statbuf->st_size = EXT2_I_SIZE(&inode);
    statbuf->st_blksize = fs->blocksize;
    statbuf->st_blocks = ext2fs_get_stat_i_blocks(fs,
                                                  (struct ext2_inode *)&inode);
    EXT4_INODE_GET_XTIME(i_atime, &tv, &inode);
    statbuf->st_atime = tv.tv_sec;
    EXT4_INODE_GET_XTIME(i_mtime, &tv, &inode);
    statbuf->st_mtime = tv.tv_sec;
    EXT4_INODE_GET_XTIME(i_ctime, &tv, &inode);
    statbuf->st_ctime = tv.tv_sec;
    if (LINUX_S_ISCHR(inode.i_mode) ||
        LINUX_S_ISBLK(inode.i_mode)) {
        if (inode.i_block[0])
            statbuf->st_rdev = inode.i_block[0];
        else
            statbuf->st_rdev = inode.i_block[1];
    }

    return 0;
}

int do_ext2fs_readdir(ext2_filsys fs, const char *path, std::vector<::dirent> *dirs) {
    ext2_ino_t ino = string_to_inode(fs, path, 1);
    if (ino == 0) {
        return -ENOENT;
    }
    ext2_file_t file;
    errcode_t ret = ext2fs_file_open(
        fs,
        ino,  // inode,
        0,    // flags TODO
        &file);
    if (ret) return translate_error(fs, ino, ret);
    ret = ext2fs_check_directory(fs, ino);
    if (ret) return translate_error(fs, ino, ret);
    auto block_buf = (char *)malloc(fs->blocksize);
    ret = ext2fs_dir_iterate(
        fs,
        ino,
        0,  // flags
        block_buf,
        copy_dirent_to_result,
        (void *)dirs);
    free(block_buf);
    if (ret) return translate_error(fs, ino, ret);

    return 0;
}

#define DO_EXT2FS(func) \
    auto ret = func;    \
    if (ret < 0) {      \
        errno = -ret;   \
        return -1;      \
    }                   \
    return ret;

class ExtFile : public photon::fs::IFile {
public:
    ExtFile(ext2_file_t _file) : file(_file) {}

    ~ExtFile() {
        close();
    }

    ssize_t pread(void *buf, size_t count, off_t offset) override{
        DO_EXT2FS(do_ext2fs_read(file, O_RDONLY, (char *)buf, count, offset))
    }
    ssize_t pwrite(const void *buf, size_t count, off_t offset) override {
        DO_EXT2FS(do_ext2fs_write(file, O_RDWR, (const char *)buf, count, offset))
    }
    int fchmod(mode_t mode) override {
        DO_EXT2FS(do_ext2fs_chmod(file, mode))
    }
    int fchown(uid_t owner, gid_t group) override {
        DO_EXT2FS(do_ext2fs_chown(file, owner, group))
    }
    int futimes(const struct timeval tv[2]) {
        DO_EXT2FS(do_ext2fs_utimes(file, tv))
    }
    int close() override{
        DO_EXT2FS(ext2fs_file_close(file))}

    UNIMPLEMENTED_POINTER(photon::fs::IFileSystem *filesystem() override);
    UNIMPLEMENTED(ssize_t preadv(const struct iovec *iov, int iovcnt, off_t offset) override);
    UNIMPLEMENTED(ssize_t pwritev(const struct iovec *iov, int iovcnt, off_t offset) override);
    UNIMPLEMENTED(off_t lseek(off_t offset, int whence) override);
    UNIMPLEMENTED(int fsync() override);
    UNIMPLEMENTED(int fdatasync() override);
    UNIMPLEMENTED(int fstat(struct stat *buf) override);
    UNIMPLEMENTED(int ftruncate(off_t length) override);
    UNIMPLEMENTED(ssize_t read(void *buf, size_t count) override);
    UNIMPLEMENTED(ssize_t readv(const struct iovec *iov, int iovcnt) override);
    UNIMPLEMENTED(ssize_t write(const void *buf, size_t count) override);
    UNIMPLEMENTED(ssize_t writev(const struct iovec *iov, int iovcnt) override);

private:
    ext2_file_t file;
};

class ExtDIR : public photon::fs::DIR {
public:
    std::vector<::dirent> m_dirs;
    ::dirent *direntp = nullptr;
    long loc;
    ExtDIR(std::vector<::dirent> &dirs) : loc(0) {
        m_dirs = std::move(dirs);
        next();
    }
    virtual ~ExtDIR() override {
        closedir();
    }
    virtual int closedir() override {
        if (!m_dirs.empty()) {
            m_dirs.clear();
        }
        return 0;
    }
    virtual dirent *get() override {
        return direntp;
    }
    virtual int next() override {
        if (!m_dirs.empty()) {
            if (loc < (long) m_dirs.size()) {
                direntp = &m_dirs[loc++];
            } else {
                direntp = nullptr;
            }
        }
        return direntp != nullptr ? 1 : 0;
    }
    virtual void rewinddir() override {
        loc = 0;
        next();
    }
    virtual void seekdir(long loc) override {
        this->loc = loc;
        next();
    }
    virtual long telldir() override {
        return loc;
    }
};

class ExtFileSystem : public photon::fs::IFileSystem {
public:
    ext2_filsys fs;
    IOManager *extfs_manager = nullptr;
    ExtFileSystem(photon::fs::IFile *_image_file) {
        extfs_manager = new_io_manager(_image_file);
        fs = do_ext2fs_open(extfs_manager->get_io_manager());
    }
    ~ExtFileSystem() {
        if (fs)
            ext2fs_close(fs);
        delete extfs_manager;
    }
    photon::fs::IFile *open(const char *pathname, int flags, mode_t mode) override {
        ext2_file_t file = do_ext2fs_open_file(fs, pathname, flags, mode);
        if (!file) {
            return nullptr;
        }
        return new ExtFile(file);
    }
    photon::fs::IFile *open(const char *pathname, int flags) override {
        return open(pathname, flags, 0666);
    }

    int mkdir(const char *pathname, mode_t mode) override {
        DO_EXT2FS(do_ext2fs_mkdir(fs, pathname, mode))
    }
    int rmdir(const char *pathname) override {
        DO_EXT2FS(do_ext2fs_rmdir(fs, pathname))
    }
    int symlink(const char *oldname, const char *newname) override {
        DO_EXT2FS(do_ext2fs_symlink(fs, oldname, newname))
    }
    int link(const char *oldname, const char *newname) override {
        DO_EXT2FS(do_ext2fs_link(fs, oldname, newname))
    }
    int rename(const char *oldname, const char *newname) override {
        DO_EXT2FS(do_ext2fs_rename(fs, oldname, newname))
    }
    int unlink(const char *filename) override {
        DO_EXT2FS(do_ext2fs_unlink(fs, filename))
    }
    int mknod(const char *path, mode_t mode, dev_t dev) override {
        DO_EXT2FS(do_ext2fs_mknod(fs, path, mode, dev))
    }
    int utime(const char *path, const struct utimbuf *file_times) override {
        auto *file = (ExtFile *)this->open(path, O_RDWR);
        if (file == nullptr) {
            return -1;
        }
        DEFER({ delete file; });
        struct timeval tm[2];
        tm[0].tv_sec = file_times->actime;
        tm[0].tv_usec = 0;
        tm[1].tv_sec = file_times->modtime;
        tm[1].tv_usec = 0;
        return file->futimes(tm);
    }
    int utimes(const char *path, const struct timeval tv[2]) override {
        auto *file = (ExtFile *)this->open(path, O_RDWR);
        if (file == nullptr) {
            return -1;
        }
        DEFER({ delete file; });
        return file->futimes(tv);
    }
    int lutimes(const char *path, const struct timeval tv[2]) override {
        auto *file = (ExtFile *)this->open(path, O_RDWR | O_NOFOLLOW);
        if (file == nullptr) {
            return -1;
        }
        DEFER({ delete file; });
        return file->futimes(tv);
        return 0;
    }
    int chown(const char *pathname, uid_t owner, gid_t group) override {
        photon::fs::IFile *file = this->open(pathname, 0);
        if (file == nullptr) {
            return -1;
        }
        DEFER({ delete file; });
        return file->fchown(owner, group);
    }
    int lchown(const char *pathname, uid_t owner, gid_t group) override {
        photon::fs::IFile *file = this->open(pathname, O_NOFOLLOW);
        if (file == nullptr) {
            return -1;
        }
        DEFER({ delete file; });
        return file->fchown(owner, group);
    }
    int chmod(const char *pathname, mode_t mode) override {
        photon::fs::IFile *file = this->open(pathname, O_NOFOLLOW);
        if (file == nullptr) {
            return -1;
        }
        DEFER({ delete file; });
        return file->fchmod(mode);
    }
    int stat(const char *path, struct stat *buf) override {
        DO_EXT2FS(do_ext2fs_stat(fs, path, buf, 1))
    }
    int lstat(const char *path, struct stat *buf) override{
        DO_EXT2FS(do_ext2fs_stat(fs, path, buf, 0))}

    photon::fs::DIR *opendir(const char *path) override {
        std::vector<::dirent> dirs;
        auto ret = do_ext2fs_readdir(fs, path, &dirs);
        if (ret) {
            errno = -ret;
            return nullptr;
        }
        return new ExtDIR(dirs);
    }

    IFileSystem *filesystem() {
        return this;
    }

    UNIMPLEMENTED_POINTER(photon::fs::IFile *creat(const char *, mode_t) override);
    UNIMPLEMENTED(ssize_t readlink(const char *filename, char *buf, size_t bufsize) override);
    UNIMPLEMENTED(int statfs(const char *path, struct statfs *buf) override);
    UNIMPLEMENTED(int statvfs(const char *path, struct statvfs *buf) override);
    UNIMPLEMENTED(int access(const char *pathname, int mode) override);
    UNIMPLEMENTED(int truncate(const char *path, off_t length) override);
    UNIMPLEMENTED(int syncfs() override);
};

photon::fs::IFileSystem *new_extfs(photon::fs::IFile *file) {
    auto extfs = new ExtFileSystem(file);
    return extfs->fs ? extfs : nullptr;
}

extern "C" {
#include "mkfs/mke2fs.h"
}

int make_extfs(photon::fs::IFile *file, const char *device_name) {
    struct stat st;
    auto ret = file->fstat(&st);
    if (ret) return ret;
    size_t size = st.st_size / DEFAULT_BLOCK_SIZE;

    std::stringstream cmd;
    cmd.clear();
    cmd << "mkfs -t ext4 -b " << DEFAULT_BLOCK_SIZE
        << " -O ^has_journal,sparse_super,flex_bg -G 1 -E discard -F "
        << device_name << " " << size;
    LOG_INFO(VALUE(cmd.str()));

    std::vector<char *> args;
    std::string token;
    while(cmd >> token) {
        char *arg = new char[token.size() + 1];
        copy(token.begin(), token.end(), arg);
        arg[token.size()] = '\0';
        args.push_back(arg);
    }
    args.push_back(0);

    auto manager = new_io_manager(file);
    DEFER(delete manager);
    ret = ext2fs_mkfs(manager->get_io_manager(), args.size()-1, &args[0]);

    for (size_t i = 0; i < args.size(); i++)
        delete args[i];

    return ret;
}