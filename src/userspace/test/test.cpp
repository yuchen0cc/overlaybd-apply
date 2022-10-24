#include "../user.h"
#include <fcntl.h>
#include <dirent.h>
#include <utime.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <photon/photon.h>
#include <photon/fs/localfs.h>
#include <photon/fs/path.h>
#include <photon/common/enumerable.h>
#include <photon/common/alog.h>
#include <photon/common/alog-stdstring.h>

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
    while (aa.size() < 2 * 1024 * 1024)
        aa.append(bb);
	auto ret = file->pwrite(aa.data(), aa.size(), 0);
	if (ret != aa.size()) {
		LOG_ERRNO_RETURN(0, -1, "failed write file ", VALUE(aa.size()), VALUE(ret))
	}
	LOG_DEBUG("write ` byte", ret);
	return 0;
}

int stat_file(photon::fs::IFileSystem *fs, const char *path, bool print = false) {
	struct stat st;
	auto ret = fs->stat(path, &st);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed stat ", VALUE(path));
	}
	if (print)
		print_stat(path, &st);
	return 0;
}

int lstat_file(photon::fs::IFileSystem *fs, const char *path, bool print = false) {
	struct stat st;
	auto ret = fs->lstat(path, &st);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed stat ", VALUE(path));
	}
	if (print)
		print_stat(path, &st);
	return 0;
}

int mkdir(photon::fs::IFileSystem *fs, const char *path) {
	auto ret = fs->mkdir(path, 0755);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed mkdir ", VALUE(path));
	}
	return 0;
}

int rmdir(photon::fs::IFileSystem *fs, const char *path) {
	auto ret = fs->rmdir(path);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed rmdir ", VALUE(path));
	}
	return 0;
}

int rename(photon::fs::IFileSystem *fs, const char *oldname, const char *newname) {
	auto ret = fs->rename(oldname, newname);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed rename ", VALUE(oldname), VALUE(newname));
	}
	return 0;
}

int chmod(photon::fs::IFileSystem *fs, const char *path, mode_t mode) {
	auto ret = fs->chmod(path, mode);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed chmod ", VALUE(path), VALUE(mode));
	}
	return 0;
}

int chown(photon::fs::IFileSystem *fs, const char *path, uid_t owner, gid_t group) {
	auto ret = fs->chown(path, owner, group);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed chown ", VALUE(path), VALUE(owner), VALUE(group));
	}
	return 0;
}

int lchown(photon::fs::IFileSystem *fs, const char *path, uid_t owner, gid_t group) {
	auto ret = fs->lchown(path, owner, group);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed lchown ", VALUE(path), VALUE(owner), VALUE(group));
	}
	return 0;
}


int link(photon::fs::IFileSystem *fs, const char *oldname, const char *newname) {
	auto ret = fs->link(oldname, newname);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed link ", VALUE(oldname), VALUE(newname));
	}
	return 0;
}

int symlink(photon::fs::IFileSystem *fs, const char *oldname, const char *newname) {
	auto ret = fs->symlink(oldname, newname);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed symlink ", VALUE(oldname), VALUE(newname));
	}
	return 0;
}

int unlink(photon::fs::IFileSystem *fs, const char *path) {
	auto ret = fs->unlink(path);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed unlink ", VALUE(path));
	}
	return 0;
}

int mknod(photon::fs::IFileSystem *fs, const char *path, mode_t mode, dev_t dev) {
	auto ret = fs->mknod(path, mode, dev);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed mknod ", VALUE(path), VALUE(mode), VALUE(dev));
	}
	return 0;
}

int utime(photon::fs::IFileSystem *fs, const char *path, const struct utimbuf *file_times) {
	auto ret = fs->utime(path, file_times);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed utime ", VALUE(path));
	}
	return 0;
}

int utimes(photon::fs::IFileSystem *fs, const char *path, const struct timeval tv[2]) {
	auto ret = fs->utimes(path, tv);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed utimes ", VALUE(path));
	}
	return 0;
}

int lutimes(photon::fs::IFileSystem *fs, const char *path, const struct timeval tv[2]) {
	auto ret = fs->lutimes(path, tv);
	if (ret) {
		LOG_ERRNO_RETURN(0, -1, "failed utimes ", VALUE(path));
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
	LOG_INFO("walk dir ", VALUE(path));
	int count = 0;
	for (auto file : enumerable(photon::fs::Walker(fs, path))) {
		auto fn = std::string(file);
		LOG_INFO(VALUE(fn));
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
    if (fs->lstat(path.c_str(), &statBuf) == 0) {        // get stat
        if (S_ISDIR(statBuf.st_mode) == 0) {      // not dir
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
 
int test() {
	int ret;
	std::string rootfs = "/tmp/rootfs.img";

	// mkfs
	std::string cmd = "mkfs.ext4 -F -b 4096 " + rootfs + " 100M";
	ret = system(cmd.c_str());
	if (ret != 0) {
		LOG_ERRNO_RETURN(0, -1, "failed mkfs");
	}
	
	// new ufs
	photon::fs::IFile *image_file = photon::fs::open_localfile_adaptor(rootfs.c_str(), O_RDWR, 0644, 0);
	if (!image_file) {
		LOG_ERRNO_RETURN(0, -1, "failed to open `", rootfs);
	}
	photon::fs::IFileSystem *fs = new_userspace_fs(image_file);
	if (!fs) {
		LOG_ERRNO_RETURN(0, -1, "failed open fs");
	}
	DEFER({delete fs;});

	// reg file
	photon::fs::IFile *file;
	file = new_file(fs, "/file1");
	assert(file != nullptr);

	ret = write_file(file);
	assert(ret == 0);

	char buf[16];
	ret = file->pread(buf, 16, 0);
	assert(ret == 16 && memcmp(buf, "abcdefghijklmnop", 16) == 0);
	ret = file->pread(buf, 16, 16384);
	assert(ret == 16 && memcmp(buf, "abcdefghijklmnop", 16) == 0);

	// stat
	ret = stat_file(fs, "/file1");
	assert(ret == 0);

	// mkdir
	ret = mkdir(fs, "/dir1");
	assert(ret == 0);
	stat_file(fs, "/dir1");
	ret = mkdir(fs, "/dir1/subdir1");
	assert(ret == 0);
	ret = mkdir(fs, "/file1");
	assert(ret == -1 && errno == EEXIST);
	ret = mkdir(fs, "/dir2/dir2");
	assert(ret == -1 && errno == ENOTDIR);
	// rmdir
	ret = mkdir(fs, "/dir2");
	assert(ret == 0);
	ret = rmdir(fs, "/dir2");
	assert(ret == 0);
	ret = stat_file(fs, "/dir2");
	assert(ret == -1 && errno == ENOENT);
	ret = rmdir(fs, "/dir1");
	assert(ret == -1 && errno == ENOTEMPTY);

	// link & symlink
	ret = link(fs, "/file1", "/dir1/file1_link");
	assert(ret == 0);
	ret = stat_file(fs, "/dir1/file1_link");
	assert(ret == 0);
	ret = symlink(fs, "/file1", "/dir1/file1_symlink");
	assert(ret == 0);
	ret = stat_file(fs, "dir1/file1_symlink");
	assert(ret == 0);
	ret = lstat_file(fs, "dir1/file1_symlink");
	assert(ret == 0);
	ret = link(fs, "/dir1/file1_symlink", "/file1_link");
	assert(ret == 0);
	ret = stat_file(fs, "/file1_link");
	assert(ret == 0);
	ret = lstat_file(fs, "/file1_link");
	assert(ret == 0);
	ret = symlink(fs, "../file2", "/dir1/file2_symlink");
	assert(ret == 0);
	ret = stat_file(fs, "/dir1/file2_symlink");
	assert(ret == -1 && errno == ENOENT);
	ret = lstat_file(fs, "/dir1/file2_symlink");
	assert(ret == 0);
	ret = symlink(fs, "/file2", "/dir1/file1_symlink");
	assert(ret == -1 && errno == EEXIST);
	ret = symlink(fs, "/file1", "/dir2/file1_symlink");
	assert(ret == -1 && errno == ENOENT);

	// unlink
	ret = symlink(fs, "/file2", "/dir1/file3_symlink");
	assert(ret == 0);
	ret = lstat_file(fs, "/dir1/file3_symlink");
	assert(ret == 0);
	ret = unlink(fs, "/dir1/file3_symlink");
	assert(ret == 0);
	ret = lstat_file(fs, "/dir1/file3_symlink");
	assert(ret == -1 && errno == ENOENT);

	// chmod
	ret = chmod(fs, "/file1", 0700);
	assert(ret == 0);
	ret = chmod(fs, "/file2", 0777);
	assert(ret == -1 && errno == ENOENT);
	ret = chmod(fs, "/dir1", 0777);

	// chown
	ret = chown(fs, "/dir1", 1001, 1001);
	assert(ret == 0);
	ret = chown(fs, "/dir1/file1_symlink", 1001, 1001);
	assert(ret == 0);
	ret = chown(fs, "/dir1/file2_symlink", 1001, 1001);
	assert(ret == -1 && errno == ENOENT);
	file = new_file(fs, "/file2");
	assert(file != nullptr);
	ret = lchown(fs, "/dir1/file2_symlink", 1001, 1001);
	assert(ret == 0);
	ret = chown(fs, "/dir1/file2_symlink", 1001, 1001);
	assert(ret == 0);
	ret = unlink(fs, "/file2");
	assert(ret == 0);

	// rename
	ret = rename(fs, "/file1", "/file2");
	assert(ret == 0);
	ret = rename(fs, "/file2", "/dir1");
	assert(ret == -1 && errno == ENOTEMPTY);
	ret = rename(fs, "/dir1", "/dir2");
	assert(ret == 0);
	ret = rename(fs, "/file2", "/dir2/file2");
	assert(ret == 0);
	ret = rename(fs, "/file2", "/dir2/file2");
	assert(ret == -1 && errno == ENOENT);
	ret = rename(fs, "/dir2/file2", "/dir1/file2");
	assert(ret == -1 && errno == ENOENT);
	ret = rename(fs, "/dir2/file2", "/dir2/file1_link");
	assert(ret == 0);
	file = new_file(fs, "/file2");
	assert(file != nullptr);
	ret = rename(fs, "/file2", "/dir2/file2");
	assert(ret == 0);
	ret = rename(fs, "/dir2", "/dir1");
	assert(ret == 0);

	// mknod
	ret = mkdir(fs, "/dev");
	assert(ret == 0);
	ret = mknod(fs, "/dev/blkdev", 0755 | S_IFBLK, makedev(240, 0));
	assert(ret == 0);
	ret = stat_file(fs, "/dev/blkdev", true);
	assert(ret == 0);
	ret = mknod(fs, "/dev/chardev", 0700 | S_IFCHR, makedev(42, 0));
	assert(ret == 0);
	ret = lstat_file(fs, "/dev/chardev", true);
	assert(ret == 0);
	ret = mknod(fs, "/fifo", S_IFIFO, makedev(0, 0));
	assert(ret == 0);
	ret = lstat_file(fs, "/fifo", true);
	assert(ret == 0);
	ret = mknod(fs, "/dev2/blkdev", 0755 | S_IFBLK, makedev(240, 0));
	assert(ret == -1 && errno == ENOTDIR);
	ret = mknod(fs, "/dev2/", 0755 | S_IFBLK, makedev(240, 0));
	assert(ret == -1 && errno == ENOTDIR);
	ret = mknod(fs, "/dev/blkdev", 0755 | S_IFBLK, makedev(240, 0));
	assert(ret == -1 && errno == EEXIST);

	// utime
	struct timeval tv[2];
	gettimeofday(&tv[0], nullptr);
	gettimeofday(&tv[1], nullptr);
	ret = link(fs, "/dir1/file1_link", "/file1");
	assert(ret == 0);
	ret = stat_file(fs, "/dir1/file1_symlink", true);
	assert(ret == 0);
	ret = lstat_file(fs, "/dir1/file1_symlink", true);
	assert(ret == 0);
	tv[0].tv_sec = tv[0].tv_sec - 3661;
	ret = utimes(fs, "/dir1/file1_symlink", tv);
	assert(ret == 0);
	ret = stat_file(fs, "/dir1/file1_symlink", true);
	assert(ret == 0);
	ret = lstat_file(fs, "/dir1/file1_symlink", true);
	assert(ret == 0);
	tv[1].tv_sec = tv[1].tv_sec - 3661;
	ret = lutimes(fs, "/dir1/file1_symlink", tv);
	assert(ret == 0);
	ret = stat_file(fs, "/dir1/file1_symlink", true);
	assert(ret == 0);
	ret = lstat_file(fs, "/dir1/file1_symlink", true);
	assert(ret == 0);
	ret = utimes(fs, "/dir1/file2_symlink", tv);
	assert(ret == -1 && errno == ENOENT);
	ret = lutimes(fs, "/dir3/file1_symlink", tv);
	assert(ret == -1 && errno == ENOENT);
	ret = lutimes(fs, "/dir1/file2_symlink", tv);
	assert(ret == 0);
	struct utimbuf ut;
	ut.actime = tv[0].tv_sec - 3661;
	ut.modtime = tv[1].tv_sec - 3661;
	ret = utime(fs, "/dir1/file1_symlink", &ut);
	assert(ret == 0);
	ret = stat_file(fs, "/dir1/file1_symlink", true);
	assert(ret == 0);
	ret = lstat_file(fs, "/dir1/file1_symlink", true);
	assert(ret == 0);
	ret = utime(fs, "/dir1/file2_symlink", &ut);
	assert(ret == -1 && errno == ENOENT);

	// readdir
	ret = opendir(fs, "/dir3");
	assert(ret == -1 && errno == ENOENT);
	ret = opendir(fs, "/");
	assert(ret == 0);
	ret = walkdir(fs, "/test");
	assert(ret == -1);
	ret = walkdir(fs, "/dir1");
	LOG_INFO("found ` file", ret);
	assert(ret > 0);
	ret = walkdir(fs, "/");
	LOG_INFO("found ` file", ret);
	assert(ret > 0);
	// rm all
	ret = remove_all(fs, "/test");
	assert(ret == -1);
	ret = remove_all(fs, "/dir1");
	assert(ret == 0);
	ret = remove_all(fs, "/");
	assert(ret == 0);

	return 0;
}

photon::fs::IFile *open_file(const char *fn, int flags, mode_t mode = 0) {
    auto file = photon::fs::open_localfile_adaptor(fn, flags, mode, 0);
    if (!file) {
		LOG_ERROR("failed to open file `, `: `", fn, errno, strerror(errno));
        exit(-1);
    }
    return file;
}

int main(int argc, char **argv) {
	photon::init(photon::INIT_EVENT_DEFAULT, photon::INIT_IO_DEFAULT);
	set_log_output_level(1);
	
	auto ret = test();
	if (ret)
		LOG_ERROR("test all failed");
	else
		LOG_INFO("test all pass");

	return 0;
}