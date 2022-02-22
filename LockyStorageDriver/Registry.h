#pragma once
#include <fltKernel.h>

#define EMPTY_UNICODE_STRING {0, 0, NULL}

NTSTATUS
LockyStorageDriverLoadData(
    _In_ PUNICODE_STRING RegistryPath,
    _Inout_ PUNICODE_STRING AppPath,
    _Inout_ PUNICODE_STRING DataPath
);