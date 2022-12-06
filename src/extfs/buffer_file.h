#pragma once
#include <photon/fs/filesystem.h>

class BufferFile;

photon::fs::IFile *new_buffer_file(photon::fs::IFile *file);