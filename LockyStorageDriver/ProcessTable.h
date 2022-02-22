#pragma once
#include <fltKernel.h>
typedef struct _ProcessTableEntry {

	HANDLE processId;
	HANDLE parentId;

} ProcessTableEntry, *PPROCESSTABLEENTRY;

RTL_GENERIC_COMPARE_RESULTS CompareProcessTableEntry(_In_ struct _RTL_AVL_TABLE* Table, _In_ PVOID  FirstStruct, _In_ PVOID  SecondStruct);
PVOID AllocateProcessTableEntry(_In_ struct _RTL_AVL_TABLE* Table, _In_ CLONG  ByteSize);
VOID FreeProcessTableEntry(_In_ struct _RTL_AVL_TABLE* Table, _In_ PVOID  Buffer);

BOOLEAN AddProcessToTable(_In_ PPROCESSTABLEENTRY entry);
BOOLEAN RemoveProcessFromTable(_In_ PPROCESSTABLEENTRY entry);
BOOLEAN IsProcessInTable(_In_ PPROCESSTABLEENTRY entry);
PVOID GetProcessInTable(_In_ PPROCESSTABLEENTRY entry);

BOOLEAN AddProcessToSystemTable(_In_ PPROCESSTABLEENTRY entry);
BOOLEAN RemoveProcessFromSystemTable(_In_ PPROCESSTABLEENTRY entry);
BOOLEAN IsProcessInSystemTable(_In_ PPROCESSTABLEENTRY entry);
PVOID GetProcessInSystemTable(_In_ PPROCESSTABLEENTRY entry);


VOID InitProcessTable();
VOID DestroyProcessTable();