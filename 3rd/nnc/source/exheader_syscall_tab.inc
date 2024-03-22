// https://www.3dbrew.org/wiki/SVC
static const char *exheader_syscall_tab[0x7E] =
{
	/* 0x00 */ NULL,
	/* 0x01 */ "ControlMemory",
	/* 0x02 */ "QueryMemory",
	/* 0x03 */ "ExitProcess",
	/* 0x04 */ "GetProcessAffinityMask",
	/* 0x05 */ "SetProcessAffinityMask",
	/* 0x06 */ "GetProcessIdealProcessor",
	/* 0x07 */ "SetProcessIdealProcessor",
	/* 0x08 */ "CreateThread",
	/* 0x09 */ "ExitThread",
	/* 0x0A */ "SleepThread",
	/* 0x0B */ "GetThreadPriority",
	/* 0x0C */ "SetThreadPriority",
	/* 0x0D */ "GetThreadAffinityMask",
	/* 0x0E */ "SetThreadAffinityMask",
	/* 0x0F */ "GetThreadIdealProcessor",
	/* 0x10 */ "SetThreadIdealProcessor",
	/* 0x11 */ "GetCurrentProcessorNumber",
	/* 0x12 */ "Run",
	/* 0x13 */ "CreateMutex",
	/* 0x14 */ "ReleaseMutex",
	/* 0x15 */ "CreateSemaphore",
	/* 0x16 */ "ReleaseSemaphore",
	/* 0x17 */ "CreateEvent",
	/* 0x18 */ "SignalEvent",
	/* 0x19 */ "ClearEvent",
	/* 0x1A */ "CreateTimer",
	/* 0x1B */ "SetTimer",
	/* 0x1C */ "CancelTimer",
	/* 0x1D */ "ClearTimer",
	/* 0x1E */ "CreateMemoryBlock",
	/* 0x1F */ "MapMemoryBlock",
	/* 0x20 */ "UnmapMemoryBlock",
	/* 0x21 */ "CreateAddressArbiter",
	/* 0x22 */ "ArbitrateAddress",
	/* 0x23 */ "CloseHandle",
	/* 0x24 */ "WaitSynchronization1",
	/* 0x25 */ "WaitSynchronizationN",
	/* 0x26 */ "SignalAndWait",
	/* 0x27 */ "DuplicateHandle",
	/* 0x28 */ "GetSystemTick",
	/* 0x29 */ "GetHandleInfo",
	/* 0x2A */ "GetSystemInfo",
	/* 0x2B */ "GetProcessInfo",
	/* 0x2C */ "GetThreadInfo",
	/* 0x2D */ "ConnectToPort",
	/* 0x2E */ "SendSyncRequest1",
	/* 0x2F */ "SendSyncRequest2",
	/* 0x30 */ "SendSyncRequest3",
	/* 0x31 */ "SendSyncRequest4",
	/* 0x32 */ "SendSyncRequest",
	/* 0x33 */ "OpenProcess",
	/* 0x34 */ "OpenThread",
	/* 0x35 */ "GetProcessId",
	/* 0x36 */ "GetProcessIdOfThread",
	/* 0x37 */ "GetThreadId",
	/* 0x38 */ "GetResourceLimit",
	/* 0x39 */ "GetResourceLimitLimitValues",
	/* 0x3A */ "GetResourceLimitCurrentValues",
	/* 0x3B */ "GetThreadContext",
	/* 0x3C */ "Break",
	/* 0x3D */ "OutputDebugString",
	/* 0x3E */ "ControlPerformanceCounter",
	/* 0x3F */ NULL,
	/* 0x40 */ NULL,
	/* 0x41 */ NULL,
	/* 0x42 */ NULL,
	/* 0x43 */ NULL,
	/* 0x44 */ NULL,
	/* 0x45 */ NULL,
	/* 0x46 */ NULL,
	/* 0x47 */ "CreatePort",
	/* 0x48 */ "CreateSessionToPort",
	/* 0x49 */ "CreateSession",
	/* 0x4A */ "AcceptSession",
	/* 0x4B */ "ReplyAndReceive1",
	/* 0x4C */ "ReplyAndReceive2",
	/* 0x4D */ "ReplyAndReceive3",
	/* 0x4E */ "ReplyAndReceive4",
	/* 0x4F */ "ReplyAndReceive",
	/* 0x50 */ "BindInterrupt",
	/* 0x51 */ "UnbindInterrupt",
	/* 0x52 */ "InvalidateProcessDataCache",
	/* 0x53 */ "StoreProcessDataCache",
	/* 0x54 */ "FlushProcessDataCache",
	/* 0x55 */ "StartInterProcessDma",
	/* 0x56 */ "StopDma",
	/* 0x57 */ "GetDmaState",
	/* 0x58 */ "RestartDma",
	/* 0x59 */ "SetGpuProt",
	/* 0x5A */ "SetWifiEnabled",
	/* 0x5B */ NULL,
	/* 0x5C */ NULL,
	/* 0x5D */ NULL,
	/* 0x5E */ NULL,
	/* 0x5F */ NULL,
	/* 0x60 */ "DebugActiveProcess",
	/* 0x61 */ "BreakDebugProcess",
	/* 0x62 */ "TerminateDebugProcess",
	/* 0x63 */ "GetProcessDebugEvent",
	/* 0x64 */ "ContinueDebugEvent",
	/* 0x65 */ "GetProcessList",
	/* 0x66 */ "GetThreadList",
	/* 0x67 */ "GetDebugThreadContext",
	/* 0x68 */ "SetDebugThreadContext",
	/* 0x69 */ "QueryDebugProcessMemory",
	/* 0x6A */ "ReadProcessMemory",
	/* 0x6B */ "WriteProcessMemory",
	/* 0x6C */ "SetHardwareBreakPoint",
	/* 0x6D */ "GetDebugThreadParam",
	/* 0x6E */ NULL,
	/* 0x6F */ NULL,
	/* 0x70 */ "ControlProcessMemory",
	/* 0x71 */ "MapProcessMemory",
	/* 0x72 */ "UnmapProcessMemory",
	/* 0x73 */ "CreateCodeSet",
	/* 0x74 */ "RandomStub",
	/* 0x75 */ "CreateProcess",
	/* 0x76 */ "TerminateProcess",
	/* 0x77 */ "SetProcessResourceLimits",
	/* 0x78 */ "CreateResourceLimit",
	/* 0x79 */ "SetResourceLimitValues",
	/* 0x7A */ "AddCodeSegment",
	/* 0x7B */ "Backdoor",
	/* 0x7C */ "KernelSetState",
	/* 0x7D */ "QueryProcessMemory",
};