#include <ext2fs/ext2fs.h>
#include <fcntl.h>
#include <dirent.h>
#include <photon/common/alog.h>

static int __translate_error(ext2_filsys fs, errcode_t err, ext2_ino_t ino,
                             const char *file, int line);
#define translate_error(fs, ino, err) __translate_error((fs), (err), (ino), \
                                                        __FILE__, __LINE__)

/*
 * Extended fields will fit into an inode if the filesystem was formatted
 * with large inodes (-I 256 or larger) and there are not currently any EAs
 * consuming all of the available space. For new inodes we always reserve
 * enough space for the kernel's known extended fields, but for inodes
 * created with an old kernel this might not have been the case. None of
 * the extended inode fields is critical for correct filesystem operation.
 * This macro checks if a certain field fits in the inode. Note that
 * inode-size = GOOD_OLD_INODE_SIZE + i_extra_isize
 */
#define EXT4_FITS_IN_INODE(ext4_inode, field)                             \
    ((offsetof(typeof(*ext4_inode), field) +                              \
      sizeof((ext4_inode)->field)) <= ((size_t)EXT2_GOOD_OLD_INODE_SIZE + \
                                       (ext4_inode)->i_extra_isize))

static inline __u32 ext4_encode_extra_time(const struct timespec *time) {
    __u32 extra = sizeof(time->tv_sec) > 4 ? ((time->tv_sec - (__s32)time->tv_sec) >> 32) &
                                                 EXT4_EPOCH_MASK
                                           : 0;
    return extra | (time->tv_nsec << EXT4_EPOCH_BITS);
}

static inline void ext4_decode_extra_time(struct timespec *time, __u32 extra) {
    if (sizeof(time->tv_sec) > 4 && (extra & EXT4_EPOCH_MASK)) {
        __u64 extra_bits = extra & EXT4_EPOCH_MASK;
        /*
         * Prior to kernel 3.14?, we had a broken decode function,
         * wherein we effectively did this:
         * if (extra_bits == 3)
         *		 extra_bits = 0;
         */
        time->tv_sec += extra_bits << 32;
    }
    time->tv_nsec = ((extra)&EXT4_NSEC_MASK) >> EXT4_EPOCH_BITS;
}

#define EXT4_INODE_SET_XTIME(xtime, timespec, raw_inode)  \
    do {                                                  \
        (raw_inode)->xtime = (timespec)->tv_sec;          \
        if (EXT4_FITS_IN_INODE(raw_inode, xtime##_extra)) \
            (raw_inode)->xtime##_extra =                  \
                ext4_encode_extra_time(timespec);         \
    } while (0)

#define EXT4_INODE_GET_XTIME(xtime, timespec, raw_inode)        \
    do {                                                        \
        (timespec)->tv_sec = (signed)((raw_inode)->xtime);      \
        if (EXT4_FITS_IN_INODE(raw_inode, xtime##_extra))       \
            ext4_decode_extra_time((timespec),                  \
                                   (raw_inode)->xtime##_extra); \
        else                                                    \
            (timespec)->tv_nsec = 0;                            \
    } while (0)

static void get_now(struct timespec *now) {
#ifdef CLOCK_REALTIME
    if (!clock_gettime(CLOCK_REALTIME, now))
        return;
#endif

    now->tv_sec = time(NULL);
    now->tv_nsec = 0;
}

static void increment_version(struct ext2_inode *inode) {
    inode->osd1.linux1.l_i_version++;
}

// static void increment_version(struct ext2_inode_large *inode)
// {
// 	__u64 ver;

// 	ver = inode->osd1.linux1.l_i_version;
// 	if (EXT4_FITS_IN_INODE(inode, i_version_hi))
// 		ver |= (__u64)inode->i_version_hi << 32;
// 	ver++;
// 	inode->osd1.linux1.l_i_version = ver;
// 	if (EXT4_FITS_IN_INODE(inode, i_version_hi))
// 		inode->i_version_hi = ver >> 32;
// }

static int update_ctime(ext2_filsys fs, ext2_ino_t ino,
                        struct ext2_inode_large *pinode) {
    errcode_t err;
    struct timespec now;
    struct ext2_inode_large inode;

    get_now(&now);

    /* If user already has a inode buffer, just update that */
    if (pinode) {
        increment_version((struct ext2_inode *)&inode);
        EXT4_INODE_SET_XTIME(i_ctime, &now, pinode);
        return 0;
    }

    /* Otherwise we have to read-modify-write the inode */
    memset(&inode, 0, sizeof(inode));
    err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
                                 sizeof(inode));
    if (err)
        return translate_error(fs, ino, err);

    increment_version((struct ext2_inode *)&inode);
    EXT4_INODE_SET_XTIME(i_ctime, &now, &inode);

    err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
                                  sizeof(inode));
    if (err)
        return translate_error(fs, ino, err);

    return 0;
}

static int update_mtime(ext2_filsys fs, ext2_ino_t ino,
                        struct ext2_inode_large *pinode) {
    errcode_t err;
    struct ext2_inode_large inode;
    struct timespec now;

    if (pinode) {
        get_now(&now);
        EXT4_INODE_SET_XTIME(i_mtime, &now, pinode);
        EXT4_INODE_SET_XTIME(i_ctime, &now, pinode);
        increment_version((struct ext2_inode *)pinode);
        return 0;
    }

    memset(&inode, 0, sizeof(inode));
    err = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode,
                                 sizeof(inode));
    if (err)
        return translate_error(fs, ino, err);

    get_now(&now);
    EXT4_INODE_SET_XTIME(i_mtime, &now, &inode);
    EXT4_INODE_SET_XTIME(i_ctime, &now, &inode);
    increment_version((struct ext2_inode *)&inode);

    err = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode,
                                  sizeof(inode));
    if (err)
        return translate_error(fs, ino, err);

    return 0;
}

static int update_xtime(ext2_file_t file, bool a, bool c, bool m, struct timespec *file_time = nullptr) {
    errcode_t err = 0;
    ext2_filsys fs = ext2fs_file_get_fs(file);
    ext2_ino_t ino = ext2fs_file_get_inode_num(file);
    ext2_inode *inode = ext2fs_file_get_inode(file);
    err = ext2fs_read_inode(fs, ino, inode);
    if (err)
        return translate_error(fs, ino, err);

    struct timespec now;
    if (file_time == nullptr) {
        get_now(&now);
    } else {
        now = *file_time;
    }
    if (a) {
        inode->i_atime = now.tv_sec;
    }
    if (c) {
        inode->i_ctime = now.tv_sec;
    }
    if (m) {
        inode->i_mtime = now.tv_sec;
    }
    increment_version(inode);
    err = ext2fs_write_inode(fs, ino, inode);
    if (err)
        return translate_error(fs, ino, err);

    return 0;
}

static int ext2_file_type(unsigned int mode) {
    if (LINUX_S_ISREG(mode))
        return EXT2_FT_REG_FILE;

    if (LINUX_S_ISDIR(mode))
        return EXT2_FT_DIR;

    if (LINUX_S_ISCHR(mode))
        return EXT2_FT_CHRDEV;

    if (LINUX_S_ISBLK(mode))
        return EXT2_FT_BLKDEV;

    if (LINUX_S_ISLNK(mode))
        return EXT2_FT_SYMLINK;

    if (LINUX_S_ISFIFO(mode))
        return EXT2_FT_FIFO;

    if (LINUX_S_ISSOCK(mode))
        return EXT2_FT_SOCK;

    return 0;
}

static unsigned int translate_open_flags(unsigned int flags) {
    unsigned int result = 0;
    if (flags & (O_WRONLY | O_RDWR)) {
        result |= EXT2_FILE_WRITE;
    }
    if (flags & O_CREAT) {
        result |= EXT2_FILE_CREATE;
    }
    return result;
}

static ext2_ino_t string_to_inode(ext2_filsys fs, const char *str, int follow, bool release = false);

static int unlink_file_by_name(ext2_filsys fs, const char *path) {
    errcode_t ret = 0;
    ext2_ino_t ino;

    DEFER(LOG_DEBUG("unlink ", VALUE(path), VALUE(ino), VALUE(ret)));
    char *filename = strdup(path);
    DEFER(free(filename););
    char *base_name;

    base_name = strrchr(filename, '/');
    if (base_name) {
        *base_name++ = '\0';
        ino = string_to_inode(fs, filename, 0);
        if (ino == 0) {
            ret = ENOENT;
            return -ENOENT;
        }
    } else {
        ino = EXT2_ROOT_INO;
        base_name = filename;
    }

    ret = ext2fs_unlink(fs, ino, base_name, 0, 0);
    if (ret) return translate_error(fs, ino, ret);

    return update_mtime(fs, ino, NULL);
}

static int remove_inode(ext2_filsys fs, ext2_ino_t ino) {
    errcode_t ret = 0;

    DEFER(LOG_DEBUG("remove ", VALUE(ino), VALUE(ret)));
    
    struct ext2_inode_large inode;
    memset(&inode, 0, sizeof(inode));
    ret = ext2fs_read_inode_full(fs, ino, (struct ext2_inode *)&inode, sizeof(inode));
    if (ret) return translate_error(fs, ino, ret);

    switch (inode.i_links_count) {
        case 0:
            return 0; /* XXX: already done? */
        case 1:
            inode.i_links_count--;
            inode.i_dtime = time(0);
            break;
        default:
            inode.i_links_count--;
    }

    ret = update_ctime(fs, ino, &inode);
    if (ret) return ret;

    if (inode.i_links_count)
        goto write_out;

    /* Nobody holds this file; free its blocks! */
    ret = ext2fs_free_ext_attr(fs, ino, &inode);
    if (ret)
        goto write_out;

    if (ext2fs_inode_has_valid_blocks2(fs, (struct ext2_inode *)&inode)) {
        ret = ext2fs_punch(fs, ino, (struct ext2_inode *)&inode, NULL, 0, ~0ULL);
        if (ret) {
            ret = translate_error(fs, ino, ret);
            goto write_out;
        }
    }

    ext2fs_inode_alloc_stats2(fs, ino, -1, LINUX_S_ISDIR(inode.i_mode));

write_out:
    ret = ext2fs_write_inode_full(fs, ino, (struct ext2_inode *)&inode, sizeof(inode));
    if (ret) return translate_error(fs, ino, ret);

    return 0;
}

struct rd_struct {
    ext2_ino_t parent;
    int empty;
};

static int rmdir_proc(
    ext2_ino_t dir,
    int entry,
    struct ext2_dir_entry *dirent,
    int offset,
    int blocksize,
    char *buf,
    void *priv_data) {
    struct rd_struct *rds = (struct rd_struct *)priv_data;

    if (dirent->inode == 0)
        return 0;
    if (((dirent->name_len & 0xFF) == 1) && (dirent->name[0] == '.'))
        return 0;
    if (((dirent->name_len & 0xFF) == 2) && (dirent->name[0] == '.') &&
        (dirent->name[1] == '.')) {
        rds->parent = dirent->inode;
        return 0;
    }
    rds->empty = 0;
    return 0;
}

static int __translate_error(ext2_filsys fs, errcode_t err, ext2_ino_t ino,
                             const char *file, int line) {
    int ret = err;
    int is_err = 0;

    // int disk_id = get_disk_id(fs->io);

    /* Translate ext2 error to unix error code */
    if (err < EXT2_ET_BASE) {
        ret = -ret;
        goto no_translation;
    }
    switch (err) {
        case EXT2_ET_NO_MEMORY:
        case EXT2_ET_TDB_ERR_OOM:
            ret = -ENOMEM;
            break;
        case EXT2_ET_INVALID_ARGUMENT:
        case EXT2_ET_LLSEEK_FAILED:
            ret = -EINVAL;
            break;
        case EXT2_ET_NO_DIRECTORY:
            ret = -ENOTDIR;
            break;
        case EXT2_ET_FILE_NOT_FOUND:
            ret = -ENOENT;
            break;
        case EXT2_ET_DIR_NO_SPACE:
            is_err = 1;
            /* fallthrough */
        case EXT2_ET_TOOSMALL:
        case EXT2_ET_BLOCK_ALLOC_FAIL:
        case EXT2_ET_INODE_ALLOC_FAIL:
        case EXT2_ET_EA_NO_SPACE:
            ret = -ENOSPC;
            break;
        case EXT2_ET_SYMLINK_LOOP:
            ret = -EMLINK;
            break;
        case EXT2_ET_FILE_TOO_BIG:
            ret = -EFBIG;
            break;
        case EXT2_ET_TDB_ERR_EXISTS:
        case EXT2_ET_FILE_EXISTS:
        case EXT2_ET_DIR_EXISTS:
            ret = -EEXIST;
            break;
        case EXT2_ET_MMP_FAILED:
        case EXT2_ET_MMP_FSCK_ON:
            ret = -EBUSY;
            break;
        case EXT2_ET_EA_KEY_NOT_FOUND:
#ifdef ENODATA
            ret = -ENODATA;
#else
            ret = -ENOENT;
#endif
            break;
        /* Sometimes fuse returns a garbage file handle pointer to us... */
        case EXT2_ET_MAGIC_EXT2_FILE:
            ret = -EFAULT;
            break;
        case EXT2_ET_UNIMPLEMENTED:
            ret = -EOPNOTSUPP;
            break;
        case EXT2_ET_FILE_RO:
            ret = -EACCES;
            break;
        default:
            is_err = 1;
            ret = -EIO;
            break;
    }

no_translation:
    if (!is_err)
        return ret;

    std::string decode = "to be decode";
    switch (err) {
        case EXT2_ET_BAD_MAGIC:
            decode = "EXT2_ET_BAD_MAGIC";
            break;
        case EXT2_ET_DIR_NO_SPACE:
            decode = "EXT2_ET_DIR_NO_SPACE";
            break;
        case EXT2_ET_DIR_CORRUPTED:
            decode = "EXT2_ET_DIR_CORRUPTED";
            break;
        case EXT2_ET_UNEXPECTED_BLOCK_SIZE:
            decode = "EXT2_ET_UNEXPECTED_BLOCK_SIZE";
            break;
    }
    if (ino)
        LOG_ERROR("ext2fs unclassified error: (inode #`) at `:`, ecode `:`", ino, file, line, err, decode.c_str());
    else
        LOG_ERROR("ext2fs unclassified error: at `:`, ecode `:`", file, line, err, decode.c_str());

    if (fs) {
        ext2fs_mark_super_dirty(fs);
        ext2fs_flush(fs);
    }

    return ret;
}

struct update_dotdot {
    ext2_ino_t new_dotdot;
};

static int update_dotdot_helper(
    ext2_ino_t dir,
    int entry,
    struct ext2_dir_entry *dirent,
    int offset,
    int blocksize,
    char *buf,
    void *priv_data) {
    struct update_dotdot *ud = (struct update_dotdot *)priv_data;

    if (ext2fs_dirent_name_len(dirent) == 2 &&
        dirent->name[0] == '.' && dirent->name[1] == '.') {
        dirent->inode = ud->new_dotdot;
        return DIRENT_CHANGED | DIRENT_ABORT;
    }

    return 0;
}

static ext2_ino_t get_parent_dir_ino(ext2_filsys fs, const char *path) {
    char *last_slash = strrchr((char *)path, '/');
    if (last_slash == 0) {
        return 0;
    }
    unsigned int parent_len = last_slash - path;
    if (parent_len == 0) {
        return EXT2_ROOT_INO;
    }
    char *parent_path = strndup(path, parent_len);
    ext2_ino_t parent_ino = string_to_inode(fs, parent_path, 0);
    LOG_DEBUG(VALUE(path), VALUE(parent_path), VALUE(parent_ino));
    free(parent_path);
    return parent_ino;
}

static char *get_filename(const char *path) {
    char *last_slash = strrchr((char *)path, (int)'/');
    if (last_slash == nullptr) {
        return nullptr;
    }
    char *filename = last_slash + 1;
    if (strlen(filename) == 0) {
        return nullptr;
    }
    return filename;
}

static int create_file(ext2_filsys fs, const char *path, unsigned int mode, ext2_ino_t *ino) {
    ext2_ino_t parent;
    errcode_t ret = 0;
    
    DEFER(LOG_DEBUG("create ", VALUE(path), VALUE(parent), VALUE(*ino), VALUE(ret)));
    parent = get_parent_dir_ino(fs, path);
    if (parent == 0) {
        ret = ENOTDIR;
        return -ENOTDIR;
    }
    ret = ext2fs_new_inode(fs, parent, mode, 0, ino);
    if (ret) {
        return translate_error(fs, parent, ret);
    }
    char *filename = get_filename(path);
    if (filename == nullptr) {
        // This should never happen.
        ret = EISDIR;
        return -EISDIR;
    }
    ret = ext2fs_link(fs, parent, filename, *ino, EXT2_FT_REG_FILE);
    if (ret == EXT2_ET_DIR_NO_SPACE) {
        ret = ext2fs_expand_dir(fs, parent);
        if (ret) return translate_error(fs, parent, ret);
        ret = ext2fs_link(fs, parent, filename, *ino, EXT2_FT_REG_FILE);
    }
    if (ret) return translate_error(fs, parent, ret);
    if (ext2fs_test_inode_bitmap2(fs->inode_map, *ino)) {
        LOG_WARN("inode already set ", VALUE(*ino));
    }
    ext2fs_inode_alloc_stats2(fs, *ino, +1, 0);
    
    struct ext2_inode inode;
    memset(&inode, 0, sizeof(inode));
    inode.i_mode = (mode & ~LINUX_S_IFMT) | LINUX_S_IFREG;
    inode.i_atime = inode.i_ctime = inode.i_mtime = time(0);
    inode.i_links_count = 1;
    ret = ext2fs_inode_size_set(fs, &inode, 0);  // TODO: update size? also on write?
    if (ret) return translate_error(fs, 0, ret);
    if (ext2fs_has_feature_inline_data(fs->super)) {
        inode.i_flags |= EXT4_INLINE_DATA_FL;
    } else if (ext2fs_has_feature_extents(fs->super)) {
        ext2_extent_handle_t handle;
        inode.i_flags &= ~EXT4_EXTENTS_FL;
        ret = ext2fs_extent_open2(fs, *ino, &inode, &handle);
        if (ret) return translate_error(fs, 0, ret);
        ext2fs_extent_free(handle);
    }
    ret = ext2fs_write_new_inode(fs, *ino, &inode);
    if (ret) return translate_error(fs, 0, ret);
    if (inode.i_flags & EXT4_INLINE_DATA_FL) {
        ret = ext2fs_inline_data_init(fs, *ino);
        if (ret) return translate_error(fs, 0, ret);
    }
    return 0;
}

unsigned char ext2_file_type_to_d_type(int type) {
    switch (type) {
        case EXT2_FT_UNKNOWN:
            return DT_UNKNOWN;
        case EXT2_FT_REG_FILE:
            return DT_REG;
        case EXT2_FT_DIR:
            return DT_DIR;
        case EXT2_FT_CHRDEV:
            return DT_CHR;
        case EXT2_FT_BLKDEV:
            return DT_BLK;
        case EXT2_FT_FIFO:
            return DT_FIFO;
        case EXT2_FT_SOCK:
            return DT_SOCK;
        case EXT2_FT_SYMLINK:
            return DT_LNK;
        default:
            return DT_UNKNOWN;
    }
}

int array_push_dirent(std::vector<dirent> *dirs, struct ext2_dir_entry *dir, size_t len) {
    struct dirent tmpdir;
    tmpdir.d_ino = (ino_t)dir->inode;
    tmpdir.d_off = 0;  // ?
    tmpdir.d_reclen = dir->rec_len;
    tmpdir.d_type = ext2_file_type_to_d_type(ext2fs_dirent_file_type(dir));
    memset(tmpdir.d_name, 0, sizeof(tmpdir.d_name));
    memcpy(tmpdir.d_name, dir->name, len);
    dirs->emplace_back(tmpdir);
    LOG_DEBUG(VALUE(tmpdir.d_ino), VALUE(tmpdir.d_reclen), VALUE(tmpdir.d_type), VALUE(tmpdir.d_name), VALUE(len));
    return 0;
}

int copy_dirent_to_result(struct ext2_dir_entry *dirent, int offset, int blocksize, char *buf, void *priv_data) {
    size_t len = ext2fs_dirent_name_len(dirent);
    if ((strncmp(dirent->name, ".", len) != 0) &&
        (strncmp(dirent->name, "..", len) != 0)) {
        array_push_dirent((std::vector<::dirent> *)priv_data, dirent, len);
    }
    return 0;
}

static blkcnt_t blocks_from_inode(ext2_filsys fs, struct ext2_inode *inode) {
    blk64_t	ret = inode->i_blocks;

	if (ext2fs_has_feature_huge_file(fs->super)) {
		ret += ((long long) inode->osd2.linux2.l_i_blocks_hi) << 32;
		if (inode->i_flags & EXT4_HUGE_FILE_FL)
			ret *= (fs->blocksize / 512);
	}
	return ret;
}