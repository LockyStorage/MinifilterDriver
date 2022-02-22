#include "Registry.h"

NTSTATUS
LockyStorageDriverReadString(
    _In_ HANDLE hRegistryKey,
    _In_ PUNICODE_STRING ValueName,
    _Out_ PUNICODE_STRING OutputString
);

NTSTATUS
LockyStorageDriverLoadData(
    _In_ PUNICODE_STRING RegistryPath,
    _Inout_ PUNICODE_STRING AppPath,
    _Inout_ PUNICODE_STRING DataPath
)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNICODE_STRING appPath = RTL_CONSTANT_STRING(L"AppPath");
    UNICODE_STRING dataPath = RTL_CONSTANT_STRING(L"DataPath");
    HANDLE hRegistryKey;

    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    InitializeObjectAttributes(&ObjectAttributes, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    for (int n = 0; n < 1; n++) {
        status = ZwOpenKey(&hRegistryKey, KEY_QUERY_VALUE, &ObjectAttributes);
        if (!NT_SUCCESS(status)) {
            KdPrint(("LockyStorageDriver: Registry key open failed (0x%08X)\n", status));
            break;
        }

        status = LockyStorageDriverReadString(hRegistryKey, &appPath, AppPath);
        if (status != STATUS_SUCCESS) {
            KdPrint(("LockyStorageDriver: Could not get data for %wZ\n", &appPath));
            break;
        }

        status = LockyStorageDriverReadString(hRegistryKey, &dataPath, DataPath);
        if (status != STATUS_SUCCESS) {
            KdPrint(("LockyStorageDriver: Could not get data for %wZ\n", &dataPath));
            break;
        }
    }

    if (hRegistryKey) {
        ZwClose(hRegistryKey);
    }

    return status;
}

NTSTATUS
LockyStorageDriverReadString(
    _In_ HANDLE hRegistryKey,
    _In_ PUNICODE_STRING ValueName,
    _Out_ PUNICODE_STRING OutputString
) 
{
    NTSTATUS status = STATUS_SUCCESS;

    PAGED_CODE();

    for (int n = 0; n < 1; n++) {
        PKEY_VALUE_FULL_INFORMATION pKeyInfo = NULL;
        PWCHAR OutputStringBuffer = NULL;

        ULONG ulKeyInfoSize = 0;
        ULONG ulKeyInfoSizeNeeded;
        // Determine the required size of keyInfo.
        status = ZwQueryValueKey(hRegistryKey,
            ValueName,
            KeyValueFullInformation,
            pKeyInfo,
            ulKeyInfoSize,
            &ulKeyInfoSizeNeeded);

        if ((status == STATUS_BUFFER_TOO_SMALL) || (status == STATUS_BUFFER_OVERFLOW))
        {
            if (ulKeyInfoSizeNeeded == 0) {
                KdPrint(("LockyStorageDriver: Value %wZ not found\n", ValueName));
                break;
            }
            ulKeyInfoSize = ulKeyInfoSizeNeeded;

            pKeyInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ulKeyInfoSize, 'LCKY');
            if (pKeyInfo == NULL) {
                KdPrint(("LockyStorageDriver: Could not allocate memory for KeyValueInfo for %wZ\n", ValueName));
                break;
            }
            RtlZeroMemory(pKeyInfo, ulKeyInfoSize);

            status = ZwQueryValueKey(hRegistryKey, ValueName, KeyValueFullInformation, pKeyInfo, ulKeyInfoSize, &ulKeyInfoSizeNeeded);
            if (!NT_SUCCESS(status) || ulKeyInfoSize != ulKeyInfoSizeNeeded) {
                KdPrint(("LockyStorageDriver: Registry value querying failed (0x%08X) for %wZ\n", status, ValueName));
                break;
            }

            ULONG_PTR pSrc;

            pSrc = (ULONG_PTR)((PUCHAR)pKeyInfo + pKeyInfo->DataOffset);

            if (pKeyInfo->Type != REG_SZ ||
                pKeyInfo->DataLength >= MAXUSHORT ||
                pKeyInfo->DataLength <= sizeof(WCHAR)) {

                status = STATUS_INVALID_PARAMETER;
                break;
            }

            OutputStringBuffer = ExAllocatePoolWithTag(NonPagedPool, pKeyInfo->DataLength, 'LCKY');

            if (OutputStringBuffer == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            OutputString->MaximumLength = (USHORT)pKeyInfo->DataLength;
            OutputString->Buffer = OutputStringBuffer;

            RtlCopyMemory(OutputStringBuffer, (PVOID) pSrc, OutputString->MaximumLength);

            OutputString->Length = OutputString->MaximumLength;

            KdPrint(("LockyStorageDriver: Size of string (%d) for %wZ\n", wcslen(OutputString->Buffer), ValueName));

            OutputStringBuffer = NULL;

            status = STATUS_SUCCESS;
        }
        else
        {
            KdPrint(("LockyStorageDriver: Could not get key info size (0x%08X) for %wZ\n", status, ValueName));
        }

        if (OutputStringBuffer != NULL) {
            ExFreePoolWithTag(OutputStringBuffer, 'LCKY');
        }

        if (pKeyInfo != NULL) {
            ExFreePoolWithTag(pKeyInfo, 'LCKY');
        }
    }

    return status;
}