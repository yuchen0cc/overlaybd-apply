#include "../extfs.h"
#include <fcntl.h>
#include <photon/photon.h>
#include <photon/fs/localfs.h>
#include <photon/fs/aligned-file.h>
#include "overlaybd/lsmt/file.h"

photon::fs::IFile *open_file(const char *fn, int flags, mode_t mode = 0) {
    auto file = open_localfile_adaptor(fn, flags, mode, 0);
    if (!file) {
        fprintf(stderr, "failed to open file '%s', %d: %s\n", fn, errno, strerror(errno));
        exit(-1);
    }
    return file;
}

int mkfs_test() {
    int retval;
    char path_data[] = "/tmp/file.data";
    char path_index[] = "/tmp/file.index";
    uint64_t vsize = 1024 * 1024 * 1024;
    const auto flag = O_RDWR | O_CREAT | O_TRUNC;
    const auto mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    auto file_data = open_file(path_data, flag, mode);
    auto file_index = open_file(path_index, flag, mode);

    LSMT::LayerInfo args(file_data, file_index);
    args.virtual_size = vsize;
    args.sparse_rw = true;

    auto upper = LSMT::create_file_rw(args, false);
    if (!upper) {
        fprintf(stderr, "failed to create lsmt file object, possibly I/O error!\n");
        exit(-1);
    }

    retval = make_extfs(upper);
    if (retval) {
        fprintf(stderr, "failed to mkfs\n");
        exit(-1);
    }

    delete upper;
    delete file_data;
    delete file_index;

    printf("lsmt mkfs successfully\n");
    return 0;
}

int main(int argc, char **argv) {
    photon::init(photon::INIT_EVENT_DEFAULT, photon::INIT_IO_DEFAULT);
    set_log_output_level(1);

    mkfs_test();

    return 0;
}