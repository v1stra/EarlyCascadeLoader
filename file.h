#ifndef _FILEUTIL_H
#define _FILEUTIL_H

#include <windows.h>
#include <stdio.h>

typedef enum e_file_type {
    FILE_TYPE_REGULAR,
    FILE_TYPE_COMPRESSED,
    FILE_TYPE_ENCODED,
    FILE_TYPE_ENCRYPTED
} e_file_type;

typedef struct t_file {
    const char* file_name;
    const char* file_key;
    e_file_type     file_type;
    DWORD           last_error;
    LPVOID          file_map;
    SIZE_T          file_size;
    HANDLE          file_handle;
    HANDLE          map_handle;
} t_file;

void cleanup(t_file* file);
void process_file(t_file* file);
BOOL map_file(t_file* file);
BOOL open_file(t_file* file);

#endif // _FILE_H