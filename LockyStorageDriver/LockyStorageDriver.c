/*++

Module Name:

    LockyStorageDriver.c

Abstract:

    This is the main module of the LockyStorageDriver miniFilter driver.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <ntstrsafe.h>

#include "Trace.h"
#include "Registry.h"
#include "ProcessTable.h"

#define CB_PROCESS_TERMINATE 0x0001
#define CB_PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#define CB_PROCESS_VM_READ 0x0010

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

typedef struct _LOCKYSTORAGE_DATA {
    UNICODE_STRING AppPath;
    UNICODE_STRING DataPath;
    UNICODE_STRING SystemRoot;
    PDRIVER_OBJECT Driver;
} LOCKYSTORAGE_DATA;

FAST_MUTEX ProcessTableMutex;

OB_CALLBACK_REGISTRATION  CBObRegistration = { 0 };
OB_OPERATION_REGISTRATION CBOperationRegistrations[1] = { { 0 } };

typedef NTSTATUS(*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );

QUERY_INFO_PROCESS ZwQueryInformationProcess;

PFLT_FILTER gFilterHandle;
PVOID gCallbackHandle;
LOCKYSTORAGE_DATA gData;

ULONG_PTR OperationStatusCtx = 1;
BOOLEAN LockyStorageProcessRoutineSet2 = FALSE;
BOOLEAN LockyStorageObRegisterCallbacksSet = FALSE;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = PTDBG_TRACE_ROUTINES;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
LockyStorageDriverInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
LockyStorageDriverInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
LockyStorageDriverInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
LockyStorageDriverUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
LockyStorageDriverInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
LockyStorageDriverPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
LockyStorageDriverOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
LockyStorageDriverPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
LockyStorageDriverPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
LockyStorageDriverDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

VOID
LockyStorageDriverCreateProcessNotifyRoutine2(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

OB_PREOP_CALLBACK_STATUS
LockyStoragePreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
);

VOID
LockyStoragePostOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION PostInfo
);

EXTERN_C_END

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, LockyStorageDriverUnload)
#pragma alloc_text(PAGE, LockyStorageDriverInstanceQueryTeardown)
#pragma alloc_text(PAGE, LockyStorageDriverInstanceSetup)
#pragma alloc_text(PAGE, LockyStorageDriverInstanceTeardownStart)
#pragma alloc_text(PAGE, LockyStorageDriverInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {

#if 0 // TODO - List all of the requests to filter.
    { IRP_MJ_CREATE,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_CLOSE,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_READ,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_WRITE,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_SET_INFORMATION,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_QUERY_EA,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_SET_EA,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_SHUTDOWN,
      0,
      LockyStorageDriverPreOperationNoPostOperation,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_CLEANUP,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_QUERY_SECURITY,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_SET_SECURITY,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_QUERY_QUOTA,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_SET_QUOTA,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_PNP,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_MDL_READ,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      LockyStorageDriverPreOperation,
      LockyStorageDriverPostOperation },

#endif // TODO

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    LockyStorageDriverUnload,                           //  MiniFilterUnload

    LockyStorageDriverInstanceSetup,                    //  InstanceSetup
    LockyStorageDriverInstanceQueryTeardown,            //  InstanceQueryTeardown
    LockyStorageDriverInstanceTeardownStart,            //  InstanceTeardownStart
    LockyStorageDriverInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
LockyStorageDriverInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are always created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("LockyStorageDriver!LockyStorageDriverInstanceSetup: Entered\n") );

    if (VolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM && VolumeFilesystemType == FLT_FSTYPE_NTFS) {
        return STATUS_SUCCESS;
    }

    return STATUS_FLT_DO_NOT_ATTACH;
}


NTSTATUS
LockyStorageDriverInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("LockyStorageDriver!LockyStorageDriverInstanceQueryTeardown: Entered\n") );

    return STATUS_FLT_DO_NOT_DETACH;
}


VOID
LockyStorageDriverInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("LockyStorageDriver!LockyStorageDriverInstanceTeardownStart: Entered\n") );
}


VOID
LockyStorageDriverInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is being deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("LockyStorageDriver!LockyStorageDriverInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Routine can return non success error codes.

--*/
{
    NTSTATUS status;

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("LockyStorageDriver!DriverEntry: Entered\n") );

    UNICODE_STRING appPath = EMPTY_UNICODE_STRING;
    UNICODE_STRING dataPath = EMPTY_UNICODE_STRING;

    LockyStorageDriverLoadData(RegistryPath, &appPath, &dataPath);

    gData.AppPath = appPath;
    gData.DataPath = dataPath;
    gData.Driver = DriverObject;

    ExInitializeFastMutex(&ProcessTableMutex);

    ExAcquireFastMutex(&ProcessTableMutex);
    InitProcessTable();
    ExReleaseFastMutex(&ProcessTableMutex);

    KdPrint(("RegistryPath: %wZ\n", RegistryPath));
    KdPrint(("AppPath: %wZ\n", gData.AppPath));
    KdPrint(("DataPath: %wZ\n", gData.DataPath));

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }

    UNICODE_STRING Altitude;
    RtlInitUnicodeString(&Altitude, L"80000");

    CBOperationRegistrations[0].ObjectType = PsProcessType;
    CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
    CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
    CBOperationRegistrations[0].PreOperation = LockyStoragePreOperationCallback;
    CBOperationRegistrations[0].PostOperation = LockyStoragePostOperationCallback;

    CBObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    CBObRegistration.Altitude = Altitude;
    CBObRegistration.OperationRegistrationCount = 1;
    CBObRegistration.RegistrationContext = &CBOperationRegistrations;
    CBObRegistration.OperationRegistration = CBOperationRegistrations;

    status = ObRegisterCallbacks(&CBObRegistration, &gCallbackHandle);

    if (!NT_SUCCESS(status)) {
        KdPrint(("LockyStorageDriver: ObRegisterCallbacks Failed!"));

        return STATUS_DRIVER_INTERNAL_ERROR;
    }

    LockyStorageObRegisterCallbacksSet = TRUE;

    //Register CreateProcess routine
    status = PsSetCreateProcessNotifyRoutineEx(LockyStorageDriverCreateProcessNotifyRoutine2, FALSE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LockyStorageDriver: Couldn't set ProcessNotifyRoutine (0x%08X)", status));
        return status;
    }

    return status;
}

NTSTATUS
LockyStorageDriverUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unload indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    NTSTATUS status;

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("LockyStorageDriver!LockyStorageDriverUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

    status = PsSetCreateProcessNotifyRoutineEx(LockyStorageDriverCreateProcessNotifyRoutine2, TRUE);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LockyStorageDriver: Couldn't unload ProcessNotifyRoutine (0x%08X)", status));
        return status;
    }

    //if (Flags != FLTFL_FILTER_UNLOAD_MANDATORY) {
    //    return status;
    //}

    if (LockyStorageObRegisterCallbacksSet && gCallbackHandle != NULL) {
        ObUnRegisterCallbacks(gCallbackHandle);
    }

    ExAcquireFastMutex(&ProcessTableMutex);
    DestroyProcessTable();
    ExReleaseFastMutex(&ProcessTableMutex);

    ExFreePoolWithTag(gData.AppPath.Buffer, 'LCKY');
    ExFreePoolWithTag(gData.DataPath.Buffer, 'LCKY');
    ExFreePoolWithTag(gData.SystemRoot.Buffer, 'LCKY');

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
#pragma prefast(disable:6001, "Not valid for kernel mode drivers")
FLT_PREOP_CALLBACK_STATUS
LockyStorageDriverPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("LockyStorageDriver!LockyStorageDriverPreOperation: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (LockyStorageDriverDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    LockyStorageDriverOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("LockyStorageDriver!LockyStorageDriverPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }

    PFLT_FILE_NAME_INFORMATION info;

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &info);

    if (NT_SUCCESS(status)) {
        if (Data->Iopb->MajorFunction == IRP_MJ_WRITE || (Data->Iopb->MajorFunction == IRP_MJ_SET_INFORMATION && Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation)) {
            //Check if File is in AppPath
            if (wcsncmp(gData.AppPath.Buffer, info->Name.Buffer, wcslen(gData.AppPath.Buffer))) {
                PEPROCESS process = FltGetRequestorProcess(Data);
                HANDLE processId = PsGetProcessId(process);

                ProcessTableEntry entry;
                entry.processId = processId;

                ExAcquireFastMutex(&ProcessTableMutex);
                if (!IsProcessInTable(&entry)) {
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;

                    return FLT_PREOP_COMPLETE;
                }
                ExReleaseFastMutex(&ProcessTableMutex);
            }

            if (wcsncmp(gData.DataPath.Buffer, info->Name.Buffer, wcslen(gData.DataPath.Buffer))) {
                PEPROCESS process = FltGetRequestorProcess(Data);
                HANDLE processId = PsGetProcessId(process);

                ProcessTableEntry entry;
                entry.processId = processId;

                ExAcquireFastMutex(&ProcessTableMutex);
                if (!IsProcessInTable(&entry)) {
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;

                    return FLT_PREOP_COMPLETE;
                }
                ExReleaseFastMutex(&ProcessTableMutex);
            }
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
LockyStorageDriverOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("LockyStorageDriver!LockyStorageDriverOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("LockyStorageDriver!LockyStorageDriverOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
LockyStorageDriverPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("LockyStorageDriver!LockyStorageDriverPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
LockyStorageDriverPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("LockyStorageDriver!LockyStorageDriverPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
LockyStorageDriverDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}

NTSTATUS GetProcessName(
    _In_ HANDLE hProcess,
    _Out_ PUNICODE_STRING Name
)
{
    NTSTATUS status;
    ULONG returnedLength;
    PVOID buffer;
    PUNICODE_STRING imageName;

    PAGED_CODE();

    if (NULL == ZwQueryInformationProcess) {
        UNICODE_STRING routineName;

        RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");

        ZwQueryInformationProcess =
            (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

        if (NULL == ZwQueryInformationProcess) {
            DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
        }
    }

    status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, NULL, 0, &returnedLength);

    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return status;
    }

    buffer = ExAllocatePoolWithTag(PagedPool, returnedLength, 'LCKY');

    if (buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryInformationProcess(hProcess,
        ProcessImageFileName,
        buffer,
        returnedLength,
        &returnedLength);

    if (NT_SUCCESS(status)) {
        imageName = (PUNICODE_STRING)buffer;

        RtlCopyUnicodeString(Name, imageName);
    }

    ExFreePoolWithTag(buffer, 'LCKY');

    return status;
}

NTSTATUS ResolveSymbolicLink(PUNICODE_STRING Symbolic, PUNICODE_STRING Result) {
    HANDLE hSymbolicLink = NULL;

    NTSTATUS status = STATUS_SUCCESS;

    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    InitializeObjectAttributes(&ObjectAttributes, Symbolic, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenSymbolicLinkObject(&hSymbolicLink, GENERIC_READ, &ObjectAttributes);
    if (!NT_SUCCESS(status)) {
        KdPrint(("LockyStorageDriver: Open Symbolic Link Failed! (0x%08X) for %wZ\n", status, Symbolic));
    }

    ULONG ulSymbolicLinkSize = 0;

    status = ZwQuerySymbolicLinkObject(hSymbolicLink, Result, &ulSymbolicLinkSize);
    if ((status == STATUS_BUFFER_TOO_SMALL) || (status == STATUS_BUFFER_OVERFLOW)) {
        Result->Length = (USHORT)ulSymbolicLinkSize;
        Result->MaximumLength = (USHORT)ulSymbolicLinkSize;
        Result->Buffer = ExAllocatePoolWithTag(NonPagedPool, ulSymbolicLinkSize, 'LCKY');

        status = ZwQuerySymbolicLinkObject(hSymbolicLink, Result, &ulSymbolicLinkSize);

        if (!NT_SUCCESS(status)) {
            KdPrint(("LockyStorageDriver: Query Symbolic Link Failed! (0x%08X) for %wZ\n", status, Symbolic));

            return status;
        }
    }
    else
    {
        KdPrint(("LockyStorageDriver: Query Symbolic Link Failed! (0x%08X) for %wZ\n", status, Symbolic));
        return status;
    }

    return status;
}

VOID
LockyStorageDriverCreateProcessNotifyRoutine2(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    NTSTATUS status;
    BOOLEAN Allocated = FALSE;

    KdPrint(("New Process\n"));
    KdPrint(("AppPath: (%wZ)\n", &gData.AppPath));
    KdPrint(("CreateInfo: %d\n", CreateInfo == NULL ? 1 : 0));
    KdPrint(("PID: %d\n", ProcessId));

    //First process created, try to find system root
    if (gData.SystemRoot.Buffer == NULL) {
        UNICODE_STRING systemRoot = EMPTY_UNICODE_STRING;
        UNICODE_STRING resolved = EMPTY_UNICODE_STRING;
        UNICODE_STRING symbolicLink = EMPTY_UNICODE_STRING;
        UNICODE_STRING systemRootPath = RTL_CONSTANT_STRING(L"\\SystemRoot");

        status = ResolveSymbolicLink(&systemRootPath, &resolved);
        KdPrint(("Resolved: (0x%08X) to %wZ\n", status, &resolved));

        if (NT_SUCCESS(status)) {
            if (wcsncmp(resolved.Buffer, L"\\Device\\BootDevice", wcslen(L"\\Device\\BootDevice")) == 0) {
                UNICODE_STRING windowsPath = EMPTY_UNICODE_STRING;

                //Bytes / sizeof WCHAR minus one WCHAR because of Index
                for (int i = (resolved.Length / sizeof(WCHAR)) - sizeof(WCHAR); i >= 0; i--) {
                    if (resolved.Buffer[i] == L'\\') {
                        symbolicLink.Length = 0;
                        symbolicLink.MaximumLength = resolved.Length;
                        symbolicLink.Buffer = ExAllocatePoolWithTag(NonPagedPool, symbolicLink.MaximumLength, 'LCKY');

                        if (symbolicLink.Buffer == NULL) {
                            ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
                        }

                        RtlUnicodeStringCbCopyNEx(&symbolicLink, &resolved, i * sizeof(WCHAR), &windowsPath, 0);

                        KdPrint(("Win: %wZ\n", &windowsPath));
                        break;
                    }
                }

                status = ResolveSymbolicLink(&symbolicLink, &systemRoot);
                KdPrint(("Resolved2: (0x%08X) to %wZ\n", status, &systemRoot));

                

                if (NT_SUCCESS(status)) {

                    if (systemRoot.Buffer != NULL) {
                        ExFreePoolWithTag(resolved.Buffer, 'LCKY');
                        ExFreePoolWithTag(symbolicLink.Buffer, 'LCKY');

                        gData.SystemRoot = systemRoot;
                        KdPrint(("SystemRoot: %wZ\n", &systemRoot));
                    }
                }
            }
        }
    }

    if (CreateInfo != NULL) {
        KdPrint(("CreateInfo: %wZ\n", CreateInfo->ImageFileName));

        UNICODE_STRING name;

        PFLT_FILE_NAME_INFORMATION fileName;

        status = FltGetFileNameInformationUnsafe(CreateInfo->FileObject, 0, FLT_FILE_NAME_NORMALIZED, &fileName);

        if (!NT_SUCCESS(status)) {
            HANDLE hProcess;

            status = ObOpenObjectByPointer(Process, OBJ_KERNEL_HANDLE, NULL, 0, 0, KernelMode, &hProcess);

            if (!NT_SUCCESS(status)) {
                KdPrint(("LockyStorageDriver: Process object open failed (0x%08X) for %wZ\n", status, CreateInfo->ImageFileName));
                return;
            }

            name.Buffer = ExAllocatePoolWithTag(NonPagedPool, 260 * sizeof(WCHAR), 'LCKY');
            name.Length = 0;
            name.MaximumLength = 260 * sizeof(WCHAR);

            Allocated = TRUE;

            status = GetProcessName(hProcess, &name);
        }
        else 
        {
            name = fileName->Name;
        }

        KdPrint(("LockyStorageDriver: New Process %wZ\n", name));

        if (name.Buffer != NULL && wcsncmp(gData.AppPath.Buffer, name.Buffer, wcslen(gData.AppPath.Buffer)) == 0) {
            ProcessTableEntry entry;
            entry.processId = ProcessId;
            entry.parentId = CreateInfo->ParentProcessId;

            KdPrint(("LockyStorageDriver: Adding %wZ (PID: %d)\n", name, ProcessId));
            KdPrint(("ParentPID: %d\n", CreateInfo->ParentProcessId));

            ExAcquireFastMutex(&ProcessTableMutex);
            AddProcessToTable(&entry);
            ExReleaseFastMutex(&ProcessTableMutex);
        }

        if (gData.SystemRoot.Buffer != NULL) {
            UNICODE_STRING csrssPath;
            UNICODE_STRING servicesPath;

            UNICODE_STRING csrss = RTL_CONSTANT_STRING(L"\\Windows\\System32\\csrss.exe");
            UNICODE_STRING services = RTL_CONSTANT_STRING(L"\\Windows\\System32\\services.exe");

            csrssPath.Length = 0;
            csrssPath.MaximumLength = gData.SystemRoot.Length + csrss.Length;

            csrssPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, csrssPath.MaximumLength, 'LCKY');

            servicesPath.Length = 0;
            servicesPath.MaximumLength = gData.SystemRoot.Length + services.Length;

            servicesPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, servicesPath.MaximumLength, 'LCKY');

            RtlAppendUnicodeStringToString(&csrssPath, &gData.SystemRoot);
            RtlAppendUnicodeStringToString(&csrssPath, &csrss);

            RtlAppendUnicodeStringToString(&servicesPath, &gData.SystemRoot);
            RtlAppendUnicodeStringToString(&servicesPath, &services);

            KdPrint(("LockyStorageDriver: SystemRoot: %wZ\n", &gData.SystemRoot));
            KdPrint(("LockyStorageDriver: CSRSS: %wZ\n", &csrss));
            KdPrint(("LockyStorageDriver: Services: %wZ\n", &services));
            KdPrint(("LockyStorageDriver: CSRSS Path: %wZ\n", &csrssPath));
            KdPrint(("LockyStorageDriver: Services Path: %wZ\n", &csrssPath));

            if (name.Buffer != NULL) {
                if (gData.SystemRoot.Buffer != NULL && csrssPath.Buffer != NULL && servicesPath.Buffer != NULL) {
                    if ((wcsncmp(csrssPath.Buffer, name.Buffer, wcslen(csrssPath.Buffer)) == 0 || wcsncmp(servicesPath.Buffer, name.Buffer, wcslen(servicesPath.Buffer)) == 0)) {
                        ProcessTableEntry entry;
                        entry.processId = ProcessId;

                        KdPrint(("LockyStorageDriver: Adding system process %wZ (PID: %d)\n", name, ProcessId));
                        KdPrint(("ParentPID: %d\n", CreateInfo->ParentProcessId));

                        ExAcquireFastMutex(&ProcessTableMutex);
                        AddProcessToSystemTable(&entry);
                        ExReleaseFastMutex(&ProcessTableMutex);
                    }
                }
            }

            ExFreePoolWithTag(csrssPath.Buffer, 'LCKY');
            ExFreePoolWithTag(servicesPath.Buffer, 'LCKY');
        }
        if (Allocated) {
            ExFreePoolWithTag(name.Buffer, 'LCKY');
        }
    }
    else {
        ExAcquireFastMutex(&ProcessTableMutex);
        ProcessTableEntry entry;
        entry.processId = ProcessId;

        if (IsProcessInTable(&entry)) {
            RemoveProcessFromTable(&entry);
        }

        if (IsProcessInSystemTable(&entry)) {
            RemoveProcessFromSystemTable(&entry);
        }

        ExReleaseFastMutex(&ProcessTableMutex);
    }
}

OB_PREOP_CALLBACK_STATUS
LockyStoragePreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (PreInfo->Object == PsGetCurrentProcess()) {
        return OB_PREOP_SUCCESS;
    }

    ProcessTableEntry source;
    source.processId = PsGetCurrentProcessId();

    ProcessTableEntry target;
    target.processId = PsGetProcessId(PreInfo->Object);

    ExAcquireFastMutex(&ProcessTableMutex);

    //Target is a protected process
    if (IsProcessInTable(&target)) {
        PPROCESSTABLEENTRY entry;

        entry = GetProcessInTable(&target);

        //Source is not a protected process or system process, strip handle
        if (!IsProcessInTable(&source) && !IsProcessInSystemTable(&source) && source.processId != entry->parentId) {
            // No kernel process
            if (PreInfo->KernelHandle != 1) {
                if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE) {
                    PreInfo->Parameters->CreateHandleInformation.DesiredAccess = SYNCHRONIZE | CB_PROCESS_TERMINATE | CB_PROCESS_QUERY_LIMITED_INFORMATION;

                    KdPrint(("LockyStorageDriver: Process Access (%d) for %d from %d\n", PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess, target.processId, source.processId));
                }
                else {
                    PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess = SYNCHRONIZE | CB_PROCESS_TERMINATE | CB_PROCESS_QUERY_LIMITED_INFORMATION;

                    KdPrint(("LockyStorageDriver: Process Access (%d) for %d from %d\n", PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess, target.processId, source.processId));
                }
            }
        }
    }

    ExReleaseFastMutex(&ProcessTableMutex);

    return OB_PREOP_SUCCESS;
}



VOID
LockyStoragePostOperationCallback(
    _In_ PVOID RegistrationContext,
    _In_ POB_POST_OPERATION_INFORMATION PostInfo
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(PostInfo);
}