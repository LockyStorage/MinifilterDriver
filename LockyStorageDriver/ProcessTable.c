#include "ProcessTable.h"

RTL_AVL_TABLE gTable;
RTL_AVL_TABLE gSystemTable;

RTL_GENERIC_COMPARE_RESULTS CompareProcessTableEntry(_In_ struct _RTL_AVL_TABLE* Table, _In_ PVOID  FirstStruct, _In_ PVOID  SecondStruct) 
{
	UNREFERENCED_PARAMETER(Table);

	PPROCESSTABLEENTRY firstProcess = (PPROCESSTABLEENTRY)FirstStruct;
	PPROCESSTABLEENTRY secondProcess = (PPROCESSTABLEENTRY)SecondStruct;

	if (firstProcess->processId > secondProcess->processId) {
		return GenericGreaterThan;
	}
	else if (firstProcess->processId < secondProcess->processId) {
		return GenericLessThan;
	}

	return GenericEqual;
}

PVOID AllocateProcessTableEntry(_In_ struct _RTL_AVL_TABLE* Table, _In_ CLONG  ByteSize)
{
	UNREFERENCED_PARAMETER(Table);

	return ExAllocatePoolWithTag(NonPagedPool, ByteSize, 'LCPT');
}

VOID FreeProcessTableEntry(_In_ struct _RTL_AVL_TABLE* Table, _In_ PVOID  Buffer)
{
	UNREFERENCED_PARAMETER(Table);

	ExFreePoolWithTag(Buffer, 'LCPT');
}

BOOLEAN AddProcessToTable(_In_ PPROCESSTABLEENTRY entry) 
{
	BOOLEAN result = FALSE;

	if (RtlInsertElementGenericTableAvl(&gTable, entry, sizeof(ProcessTableEntry), &result) == NULL) {
		return FALSE;
	}

	return result;
}

BOOLEAN RemoveProcessFromTable(_In_ PPROCESSTABLEENTRY entry) {
	return RtlDeleteElementGenericTableAvl(&gTable, entry);
}

BOOLEAN IsProcessInTable(_In_ PPROCESSTABLEENTRY entry) {
	return RtlLookupElementGenericTableAvl(&gTable, entry) ? TRUE : FALSE;
}

PVOID GetProcessInTable(_In_ PPROCESSTABLEENTRY entry) {
	return RtlLookupElementGenericTableAvl(&gTable, entry);
}

BOOLEAN AddProcessToSystemTable(_In_ PPROCESSTABLEENTRY entry)
{
	BOOLEAN result = FALSE;

	if (RtlInsertElementGenericTableAvl(&gSystemTable, entry, sizeof(ProcessTableEntry), &result) == NULL) {
		return FALSE;
	}

	return result;
}

BOOLEAN RemoveProcessFromSystemTable(_In_ PPROCESSTABLEENTRY entry) {
	return RtlDeleteElementGenericTableAvl(&gSystemTable, entry);
}

BOOLEAN IsProcessInSystemTable(_In_ PPROCESSTABLEENTRY entry) {
	return RtlLookupElementGenericTableAvl(&gSystemTable, entry) ? TRUE : FALSE;
}

PVOID GetProcessInSystemTable(_In_ PPROCESSTABLEENTRY entry) {
	return RtlLookupElementGenericTableAvl(&gSystemTable, entry);
}

VOID InitProcessTable() {
	RtlInitializeGenericTableAvl(&gTable, CompareProcessTableEntry, AllocateProcessTableEntry, FreeProcessTableEntry, NULL);
	RtlInitializeGenericTableAvl(&gSystemTable, CompareProcessTableEntry, AllocateProcessTableEntry, FreeProcessTableEntry, NULL);
}

VOID DestroyProcessTable()
{
	PPROCESSTABLEENTRY entry;
	PVOID restartKey = NULL;

	for (entry = RtlEnumerateGenericTableWithoutSplayingAvl(&gTable, &restartKey);
		entry != NULL;
		entry = RtlEnumerateGenericTableWithoutSplayingAvl(&gTable, &restartKey))
	{
		if (!RtlDeleteElementGenericTableAvl(&gTable, entry)) {
			KdPrint(("LockyStorageDriver: Couldn't remove element from Table"));
			ExRaiseStatus(STATUS_DATA_ERROR);
		}
			

		restartKey = NULL; // reset to start at first one again
	}

	for (entry = RtlEnumerateGenericTableWithoutSplayingAvl(&gTable, &restartKey);
		entry != NULL;
		entry = RtlEnumerateGenericTableWithoutSplayingAvl(&gTable, &restartKey))
	{
		if (!RtlDeleteElementGenericTableAvl(&gTable, entry)) {
			KdPrint(("LockyStorageDriver: Couldn't remove element from System Table"));
			ExRaiseStatus(STATUS_DATA_ERROR);
		}

		restartKey = NULL; // reset to start at first one again
	}
}