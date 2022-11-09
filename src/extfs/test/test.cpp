#include "../extfs.h"
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <photon/photon.h>
#include <photon/fs/localfs.h>
#include <photon/fs/path.h>
#include <photon/common/alog.h>
#include <photon/common/alog-stdstring.h>
#include <photon/common/enumerable.h>
#include <gtest/gtest.h>

#define FILE_SIZE (2 * 1024 * 1024)

void print_stat(const char *path, struct stat *st) {
    printf("File: %s\n", path);
    printf("Size: %d, Blocks: %d, IO Blocks: %d, Type: %d\n", st->st_size, st->st_blocks, st->st_blksize, IFTODT(st->st_mode));
    printf("Device: %u/%u, Inode: %d, Links: %d, Device type: %u,%u\n",
           major(st->st_dev), minor(st->st_dev), st->st_ino, st->st_nlink, major(st->st_rdev), minor(st->st_rdev));
    printf("Access: %05o, Uid: %d, Gid: %d\n", st->st_mode & 0xFFF, st->st_uid, st->st_gid);
    printf("Access: %s", asctime(localtime(&(st->st_atim.tv_sec))));
    printf("Modify: %s", asctime(localtime(&(st->st_mtim.tv_sec))));
    printf("Change: %s", asctime(localtime(&(st->st_ctim.tv_sec))));
}

photon::fs::IFile *new_file(photon::fs::IFileSystem *fs, const char *path) {
    auto file = fs->open(path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (!file) {
        LOG_ERRNO_RETURN(0, nullptr, "failed open file ", VALUE(path));
    }
    return file;
}

int write_file(photon::fs::IFile *file) {
    std::string bb = "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01";
    std::string aa;
    while (aa.size() < FILE_SIZE)
        aa.append(bb);
    auto ret = file->pwrite(aa.data(), aa.size(), 0);
    if (ret != aa.size()) {
        LOG_ERRNO_RETURN(0, -1, "failed write file ", VALUE(aa.size()), VALUE(ret))
    }
    LOG_DEBUG("write ` byte", ret);
    return 0;
}

int stat(photon::fs::IFileSystem *fs, const char *path, struct stat *buf) {
    auto ret = fs->stat(path, buf);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed stat ", VALUE(path));
    }
    return 0;
}

int lstat(photon::fs::IFileSystem *fs, const char *path, struct stat *buf) {
    auto ret = fs->lstat(path, buf);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed lstat ", VALUE(path));
    }
    return 0;
}

int mkdir(photon::fs::IFileSystem *fs, const char *path) {
    auto ret = fs->mkdir(path, 0755);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed mkdir ", VALUE(path));
    }
    return 0;
}

int rmdir(photon::fs::IFileSystem *fs, const char *path) {
    auto ret = fs->rmdir(path);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed rmdir ", VALUE(path));
    }
    return 0;
}

int rename(photon::fs::IFileSystem *fs, const char *oldname, const char *newname) {
    auto ret = fs->rename(oldname, newname);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed rename ", VALUE(oldname), VALUE(newname));
    }
    return 0;
}

int chmod(photon::fs::IFileSystem *fs, const char *path, mode_t mode) {
    auto ret = fs->chmod(path, mode);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed chmod ", VALUE(path), VALUE(mode));
    }
    return 0;
}

int chown(photon::fs::IFileSystem *fs, const char *path, uid_t owner, gid_t group) {
    auto ret = fs->chown(path, owner, group);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed chown ", VALUE(path), VALUE(owner), VALUE(group));
    }
    return 0;
}

int lchown(photon::fs::IFileSystem *fs, const char *path, uid_t owner, gid_t group) {
    auto ret = fs->lchown(path, owner, group);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed lchown ", VALUE(path), VALUE(owner), VALUE(group));
    }
    return 0;
}

int link(photon::fs::IFileSystem *fs, const char *oldname, const char *newname) {
    auto ret = fs->link(oldname, newname);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed link ", VALUE(oldname), VALUE(newname));
    }
    return 0;
}

int symlink(photon::fs::IFileSystem *fs, const char *oldname, const char *newname) {
    auto ret = fs->symlink(oldname, newname);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed symlink ", VALUE(oldname), VALUE(newname));
    }
    return 0;
}

int unlink(photon::fs::IFileSystem *fs, const char *path) {
    auto ret = fs->unlink(path);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed unlink ", VALUE(path));
    }
    return 0;
}

int mknod(photon::fs::IFileSystem *fs, const char *path, mode_t mode, dev_t dev) {
    auto ret = fs->mknod(path, mode, dev);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed mknod ", VALUE(path), VALUE(mode), VALUE(dev));
    }
    return 0;
}

int utime(photon::fs::IFileSystem *fs, const char *path, const struct utimbuf *file_times) {
    auto ret = fs->utime(path, file_times);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed utime ", VALUE(path));
    }
    return 0;
}

int utimes(photon::fs::IFileSystem *fs, const char *path, const struct timeval tv[2]) {
    auto ret = fs->utimes(path, tv);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed utimes ", VALUE(path));
    }
    return 0;
}

int lutimes(photon::fs::IFileSystem *fs, const char *path, const struct timeval tv[2]) {
    auto ret = fs->lutimes(path, tv);
    if (ret) {
        LOG_ERRNO_RETURN(0, ret, "failed utimes ", VALUE(path));
    }
    return 0;
}

int opendir(photon::fs::IFileSystem *fs, const char *path) {
    auto ret = fs->opendir(path);
    if (ret == nullptr) {
        LOG_ERRNO_RETURN(0, -1, "failed opendir ", VALUE(path));
    } else {
        delete ret;
        return 0;
    }
}

int walkdir(photon::fs::IFileSystem *fs, const char *path) {
    struct stat buf;
    if (fs->lstat(path, &buf) < 0) {
        LOG_ERRNO_RETURN(0, -1, "failed to lstat ", VALUE(path));
    }
    LOG_DEBUG("walk dir ", VALUE(path));
    int count = 0;
    for (auto file : enumerable(photon::fs::Walker(fs, path))) {
        auto fn = std::string(file);
        LOG_DEBUG(VALUE(fn));
        count++;
    }
    return count;
}

int remove_all(photon::fs::IFileSystem *fs, const std::string &path) {
    if (fs == nullptr || path.empty()) {
        LOG_ERROR("remove_all ` failed, fs is null or path is empty", path);
        return -1;
    }
    struct stat statBuf;
    int ret = 0;
    if (fs->lstat(path.c_str(), &statBuf) == 0) {  // get stat
        if (S_ISDIR(statBuf.st_mode) == 0) {       // not dir
            return fs->unlink(path.c_str());
        }
    } else {
        LOG_ERRNO_RETURN(0, -1, "get path ` stat failed", path);
    }

    auto dirs = fs->opendir(path.c_str());
    if (dirs == nullptr) {
        LOG_ERRNO_RETURN(0, -1, "open dir ` failed", path);
    }
    dirent *dirInfo;
    while ((dirInfo = dirs->get()) != nullptr) {
        if (strcmp(dirInfo->d_name, ".") != 0 && strcmp(dirInfo->d_name, "..") != 0) {
            std::string npath(path);
            if (npath.back() == '/') {
                npath = npath.substr(0, npath.size() - 1);
            }
            LOG_DEBUG(VALUE(path), VALUE(npath));
            ret = remove_all(fs, npath + "/" + dirInfo->d_name);
            if (ret) return ret;
        }
        dirs->next();
    }

    fs->closedir(dirs);
    if (path == "/")
        return 0;
    ret = fs->rmdir(path.c_str());
    if (ret) return ret;

    return 0;
}

photon::fs::IFileSystem *init_extfs() {
    std::string rootfs = "/tmp/rootfs.img";
    // mkfs
    // std::string cmd = "mkfs.ext4 -F -b 4096 " + rootfs + " 100M";
    // auto ret = system(cmd.c_str());
    // if (ret != 0) {
    //     LOG_ERRNO_RETURN(0, nullptr, "failed mkfs");
    // }
    photon::fs::IFile *image_file = photon::fs::open_localfile_adaptor(rootfs.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0644, 0);
    if (!image_file) {
        LOG_ERRNO_RETURN(0, nullptr, "failed to open `", rootfs);
    }
    int ret = image_file->fallocate(0, 0, 4096 * 25600);
    if (ret) {
        LOG_ERRNO_RETURN(0, nullptr, "failed to fallocate");
    }
    ret = make_extfs(image_file, rootfs.c_str());
    if (ret) {
        LOG_ERRNO_RETURN(0, nullptr, "failed to mkfs");
    }
    delete image_file;

    // new extfs
    image_file = photon::fs::open_localfile_adaptor(rootfs.c_str(), O_RDWR, 0644, 0);
    if (!image_file) {
        LOG_ERRNO_RETURN(0, nullptr, "failed to open `", rootfs);
    }
    photon::fs::IFileSystem *extfs = new_extfs(image_file);
    if (!extfs) {
        delete image_file;
        LOG_ERRNO_RETURN(0, nullptr, "failed open fs");
    }

    return extfs;
}
class ExtfsTest : public ::testing::Test {
   protected:
    virtual void SetUp() override {
    }
    virtual void TearDown() override {
    }

    static void SetUpTestSuite() {
        fs = init_extfs();
        ASSERT_NE(nullptr, fs);
    }

    static void TearDownTestSuite() {
        if (fs)
            delete fs;
    }

    static photon::fs::IFileSystem *fs;
};

photon::fs::IFileSystem *ExtfsTest::fs = nullptr;

TEST_F(ExtfsTest, Regfile) {
    photon::fs::IFile *file = new_file(fs, "/file1");
    ASSERT_NE(nullptr, file);

    auto ret = write_file(file);
    ASSERT_EQ(0, ret);

    char buf[16];
    ret = file->pread(buf, 16, 0);
    EXPECT_EQ(16, ret);
    EXPECT_EQ(0, memcmp(buf, "abcdefghijklmnop", 16));
    ret = file->pread(buf, 16, 16384);
    EXPECT_EQ(16, ret);
    EXPECT_EQ(0, memcmp(buf, "abcdefghijklmnop", 16));
    delete file;
    // stat
    struct stat st;
    ret = stat(fs, "/file1", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(FILE_SIZE, st.st_size);
    EXPECT_EQ(DT_REG, IFTODT(st.st_mode));
}

TEST_F(ExtfsTest, Dir) {
    // mkdir
    auto ret = mkdir(fs, "/dir1");
    EXPECT_EQ(0, ret);
    struct stat st;
    ret = stat(fs, "/dir1", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(DT_DIR, IFTODT(st.st_mode));

    ret = mkdir(fs, "/dir1/subdir1");
    EXPECT_EQ(0, ret);
    ret = mkdir(fs, "/dir1");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(EEXIST, errno);
    ret = mkdir(fs, "/dir2/dir2");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOTDIR, errno);
    // rmdir
    ret = mkdir(fs, "/dir2");
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/dir2", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(DT_DIR, IFTODT(st.st_mode));
    ret = rmdir(fs, "/dir2");
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/dir2", &st);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    ret = rmdir(fs, "/dir1");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOTEMPTY, errno);
}

TEST_F(ExtfsTest, Link) {
    auto ret = link(fs, "/file1", "/dir1/file1_link");
    EXPECT_EQ(0, ret);
    struct stat st;
    ret = stat(fs, "/dir1/file1_link", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(DT_REG, IFTODT(st.st_mode));
    EXPECT_EQ(2, st.st_nlink);

    ret = symlink(fs, "/file1", "/dir1/file1_symlink");
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/dir1/file1_symlink", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(DT_REG, IFTODT(st.st_mode));
    ret = lstat(fs, "/dir1/file1_symlink", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(DT_LNK, IFTODT(st.st_mode));

    ret = link(fs, "/dir1/file1_symlink", "/file1_link");
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/file1_link", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(DT_REG, IFTODT(st.st_mode));
    ret = lstat(fs, "/file1_link", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(DT_LNK, IFTODT(st.st_mode));

    ret = symlink(fs, "../file2", "/dir1/file2_symlink");
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/dir1/file2_symlink", &st);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    ret = lstat(fs, "/dir1/file2_symlink", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(DT_LNK, IFTODT(st.st_mode));

    ret = symlink(fs, "/file2", "/dir1/file1_symlink");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(EEXIST, errno);
    ret = symlink(fs, "/file1", "/dir2/file1_symlink");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    ret = symlink(fs, "..//file1", "/dir1/file5_symlink");
    EXPECT_EQ(0, ret);
    ret = lstat(fs, "/dir1/file5_symlink", &st);
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/dir1/file5_symlink", &st);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
}

TEST_F(ExtfsTest, Unlink) {
    auto ret = symlink(fs, "/file2", "/dir1/file3_symlink");
    EXPECT_EQ(0, ret);
    struct stat st;
    ret = lstat(fs, "/dir1/file3_symlink", &st);
    EXPECT_EQ(0, ret);
    ret = unlink(fs, "/dir1/file3_symlink");
    EXPECT_EQ(0, ret);
    ret = lstat(fs, "/dir1/file3_symlink", &st);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);

    ret = unlink(fs, "/dir1/file6_symlink");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    ret = unlink(fs, "/dir1");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(EISDIR, errno);
}

TEST_F(ExtfsTest, Chmod) {
    auto ret = chmod(fs, "/file1", 0700);
    EXPECT_EQ(0, ret);
    struct stat st;
    ret = lstat(fs, "/file1", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(0700, st.st_mode & 0xFFF);

    ret = chmod(fs, "/dir1", 0777);
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/dir1", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(0777, st.st_mode & 0xFFF);

    ret = chmod(fs, "/file2", 0777);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
}

TEST_F(ExtfsTest, Chown) {
    auto ret = chown(fs, "/dir1", 1001, 1010);
    EXPECT_EQ(0, ret);
    struct stat st;
    ret = stat(fs, "/dir1", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(1001, st.st_uid);
    EXPECT_EQ(1010, st.st_gid);

    ret = chown(fs, "/dir1/file1_symlink", 1002, 1020);
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/dir1/file1_symlink", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(1002, st.st_uid);
    EXPECT_EQ(1020, st.st_gid);

    ret = chown(fs, "/dir1/file2_symlink", 1003, 1030);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    auto file = new_file(fs, "/file2");
    EXPECT_NE(nullptr, file);
    DEFER(delete file;);

    struct stat st_old;
    ret = stat(fs, "/dir1/file2_symlink", &st_old);
    EXPECT_EQ(0, ret);
    ret = lchown(fs, "/dir1/file2_symlink", 1003, 1030);
    EXPECT_EQ(0, ret);
    ret = lstat(fs, "/dir1/file2_symlink", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(1003, st.st_uid);
    EXPECT_EQ(1030, st.st_gid);
    ret = stat(fs, "/dir1/file2_symlink", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(st_old.st_uid, st.st_uid);
    EXPECT_EQ(st_old.st_gid, st.st_gid);
    ret = chown(fs, "/dir1/file2_symlink", 1004, 1040);
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/dir1/file2_symlink", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(1004, st.st_uid);
    EXPECT_EQ(1040, st.st_gid);
    EXPECT_NE(st_old.st_uid, st.st_uid);
    EXPECT_NE(st_old.st_gid, st.st_gid);
    ret = unlink(fs, "/file2");
    EXPECT_EQ(0, ret);
}

TEST_F(ExtfsTest, Mknod) {
    auto ret = mkdir(fs, "/dev");
    EXPECT_EQ(0, ret);
    ret = mknod(fs, "/dev/blkdev", 0755 | S_IFBLK, makedev(240, 0));
    EXPECT_EQ(0, ret);
    struct stat st;
    ret = stat(fs, "/dev/blkdev", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(DT_BLK, IFTODT(st.st_mode));

    ret = mknod(fs, "/dev/chardev", 0700 | S_IFCHR, makedev(42, 0));
    EXPECT_EQ(0, ret);
    ret = lstat(fs, "/dev/chardev", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(DT_CHR, IFTODT(st.st_mode));

    ret = mknod(fs, "/fifo", S_IFIFO, makedev(0, 0));
    EXPECT_EQ(0, ret);
    ret = lstat(fs, "/fifo", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(DT_FIFO, IFTODT(st.st_mode));

    ret = mknod(fs, "/dev2/blkdev", 0755 | S_IFBLK, makedev(240, 0));
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOTDIR, errno);
    ret = mknod(fs, "/dev/blkdev", 0755 | S_IFBLK, makedev(240, 0));
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(EEXIST, errno);
}

TEST_F(ExtfsTest, Utime) {
    struct timeval tv[2];
    gettimeofday(&tv[0], nullptr);
    gettimeofday(&tv[1], nullptr);

    struct stat st, lst, st_old, lst_old;
    auto ret = lstat(fs, "/dir1/file1_symlink", &lst_old);
    EXPECT_EQ(0, ret);
    tv[0].tv_sec = tv[0].tv_sec - 3661;
    ret = utimes(fs, "/dir1/file1_symlink", tv);
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/dir1/file1_symlink", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(tv[0].tv_sec, st.st_atim.tv_sec);
    EXPECT_EQ(tv[1].tv_sec, st.st_mtim.tv_sec);
    ret = lstat(fs, "/dir1/file1_symlink", &lst);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(lst_old.st_atim.tv_sec, lst.st_atim.tv_sec);
    EXPECT_EQ(lst_old.st_mtim.tv_sec, lst.st_mtim.tv_sec);

    ret = stat(fs, "/dir1/file1_symlink", &st_old);
    EXPECT_EQ(0, ret);
    tv[1].tv_sec = tv[1].tv_sec - 3661;
    ret = lutimes(fs, "/dir1/file1_symlink", tv);
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/dir1/file1_symlink", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(st_old.st_atim.tv_sec, st.st_atim.tv_sec);
    EXPECT_EQ(st_old.st_mtim.tv_sec, st.st_mtim.tv_sec);
    ret = lstat(fs, "/dir1/file1_symlink", &lst);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(tv[0].tv_sec, lst.st_atim.tv_sec);
    EXPECT_EQ(tv[1].tv_sec, lst.st_mtim.tv_sec);

    struct utimbuf ut;
    ut.actime = tv[0].tv_sec - 3661;
    ut.modtime = tv[1].tv_sec - 3661;
    ret = lstat(fs, "/dir1/file1_symlink", &lst_old);
    EXPECT_EQ(0, ret);
    ret = utime(fs, "/dir1/file1_symlink", &ut);
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/dir1/file1_symlink", &st);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(ut.actime, st.st_atim.tv_sec);
    EXPECT_EQ(ut.modtime, st.st_mtim.tv_sec);
    ret = lstat(fs, "/dir1/file1_symlink", &lst);
    EXPECT_EQ(0, ret);
    EXPECT_EQ(lst_old.st_atim.tv_sec, lst.st_atim.tv_sec);
    EXPECT_EQ(lst_old.st_mtim.tv_sec, lst.st_mtim.tv_sec);

    ret = utimes(fs, "/dir1/file2_symlink", tv);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    ret = lutimes(fs, "/dir3/file1_symlink", tv);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    ret = lutimes(fs, "/dir1/file2_symlink", tv);
    EXPECT_EQ(0, ret);
    ret = utime(fs, "/dir1/file2_symlink", &ut);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
}

TEST_F(ExtfsTest, Rename) {
    struct stat st;
    auto ret = stat(fs, "/file2", &st);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    ret = rename(fs, "/file1", "/file2");
    EXPECT_EQ(0, ret);
    ret = stat(fs, "/file1", &st);
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    ret = stat(fs, "/file2", &st);
    EXPECT_EQ(0, ret);

    ret = rename(fs, "/file2", "/dir1");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOTEMPTY, errno);
    ret = rename(fs, "/dir1", "/dir2");
    EXPECT_EQ(0, ret);
    ret = rename(fs, "/file2", "/dir2/file2");
    EXPECT_EQ(0, ret);
    ret = rename(fs, "/file2", "/dir2/file2");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    ret = rename(fs, "/dir2/file2", "/dir1/file2");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    ret = rename(fs, "/dir2/file2", "/dir2/file1_link");
    EXPECT_EQ(0, ret);
    auto file = new_file(fs, "/file2");
    EXPECT_NE(nullptr, file);
    ret = rename(fs, "/file2", "/dir2/file2");
    EXPECT_EQ(0, ret);
    ret = rename(fs, "/dir2", "/dir1");
    EXPECT_EQ(0, ret);
}

TEST_F(ExtfsTest, Readdir) {
    auto ret = opendir(fs, "/dir3");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    ret = opendir(fs, "/");
    EXPECT_EQ(0, ret);
    ret = walkdir(fs, "/test");
    EXPECT_EQ(-1, ret);
    ret = walkdir(fs, "/dir1");
    LOG_INFO("found ` file", ret);
    EXPECT_LT(0, ret);
    ret = walkdir(fs, "/");
    LOG_INFO("found ` file", ret);
    EXPECT_LT(0, ret);
    // rm all
    ret = remove_all(fs, "/test");
    EXPECT_EQ(-1, ret);
    ret = remove_all(fs, "/dir1");
    EXPECT_EQ(0, ret);
    ret = opendir(fs, "/dir1");
    EXPECT_EQ(-1, ret);
    EXPECT_EQ(ENOENT, errno);
    ret = remove_all(fs, "/");
    EXPECT_EQ(0, ret);
    ret = walkdir(fs, "/");
    LOG_INFO("found ` file", ret);
    EXPECT_EQ(0, ret);
}

int main(int argc, char **argv) {
    photon::init(photon::INIT_EVENT_DEFAULT, photon::INIT_IO_DEFAULT);
    DEFER(photon::fini(););
    set_log_output_level(1);

    ::testing::InitGoogleTest(&argc, argv);
    auto ret = RUN_ALL_TESTS();
    if (ret) LOG_ERROR_RETURN(0, ret, VALUE(ret));
}