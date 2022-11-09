#include "../extfs.h"
#include <fcntl.h>
#include <photon/photon.h>
#include <photon/fs/localfs.h>
#include <photon/fs/aligned-file.h>
#include "overlaybd/lsmt/file.h"

int mkfs_test()
{
    int retval;
    char path_data[] = "/root/overlaybd-apply/file.data";
    char path_index[] = "/root/overlaybd-apply/file.index";
    photon::fs::IFile *file_data = photon::fs::open_localfile_adaptor(path_data, O_RDWR, 0644, 0);
    photon::fs::IFile *file_index = photon::fs::open_localfile_adaptor(path_index, O_RDWR, 0644, 0);
    auto upper = LSMT::open_file_rw(file_data, file_index, true);
    auto stack_file = LSMT::stack_files(upper, nullptr, true, false);
    photon::fs::IFile *image_file = photon::fs::new_aligned_file_adaptor(stack_file, 4096, true, true);
    if (!image_file)
    {
        LOG_ERRNO_RETURN(0, -1, "failed to open lsmt upper");
    }
    // retval = image_file->fallocate(0, 0, 4096 * 25600);
    // if (retval) {
    //     LOG_ERRNO_RETURN(0, -1, "failed fallocate");
    // }
    retval = make_extfs(image_file);
    if (retval)
    {
        LOG_ERRNO_RETURN(0, -1, "failed to mkfs");
    }
}

int main(int argc, char **argv)
{
    photon::init(photon::INIT_EVENT_DEFAULT, photon::INIT_IO_DEFAULT);
    set_log_output_level(1);

    mkfs_test();

    return 0;
}