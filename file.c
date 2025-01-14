#include <windows.h>

#include "file.h"

BOOL open_file(t_file* file) {
    file->file_handle = CreateFileA(file->file_name, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (file->file_handle == INVALID_HANDLE_VALUE) {
        file->last_error = GetLastError();
        return FALSE;
    }

    return TRUE;
}

/* map large file into memory */
BOOL map_file(t_file* file) {

    LARGE_INTEGER size = { 0 };
    GetFileSizeEx(file->file_handle, &size);

    file->file_size = size.QuadPart;

    // file->map_handle = CreateFileMappingA(file->file_handle, NULL, PAGE_READWRITE, size.HighPart, size.LowPart, NULL);
    file->map_handle = CreateFileMappingA(file->file_handle, NULL, PAGE_READWRITE, 0, file->file_size, NULL);

    /* we are finished with file handle */
    CloseHandle(file->file_handle);

    file->file_handle = NULL;

    if (file->map_handle == NULL) {
        file->last_error = GetLastError();
        return FALSE;
    }

    file->file_map = MapViewOfFile(file->map_handle, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    /* we are finished with map handle */
    CloseHandle(file->map_handle);

    file->map_handle = NULL;

    if (file->file_map == NULL) {
        file->last_error = GetLastError();
        return FALSE;
    }

    return TRUE;
}

/* perform encoding, compression, or encryption on file and remap if necessary */
void process_file(t_file* file) {
    switch (file->file_type) {
    case FILE_TYPE_ENCODED:
        break;
    case FILE_TYPE_COMPRESSED:
        break;
    case FILE_TYPE_ENCRYPTED:
    {
        size_t key_len = strlen(file->file_key);
        char* map = (char*)file->file_map;
        for (int i = 0; i < file->file_size; i++) {
            map[i] = map[i] ^ file->file_key[i % key_len];
        }
    }
    default:
        break;
    }
}

void cleanup(t_file* file) {
    /* unmap view of file */
    UnmapViewOfFile(file->file_map);
}
