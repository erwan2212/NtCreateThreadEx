unit ntdll;

{$mode objfpc}{$H+}

interface

uses
  windows;

const
  ViewShare = 1;
  ViewUnmap = 2;

  ProcessImageFileName = 27;

  ProcessBasicInformation=0;

  FileDispositionInformation= 13;

  PS_INHERIT_HANDLES =4;

    NtCurrentProcess = HANDLE(-1); //$FFFFFFFF;
    NtCurrentThread =  HANDLE(-2); //$FFFFFFFE;

    TRANSACTION_QUERY_INFORMATION = $0001;
    TRANSACTION_SET_INFORMATION = $0002;
    TRANSACTION_ENLIST = $0004;
    TRANSACTION_COMMIT = $0008;
    TRANSACTION_ROLLBACK = $0010;
    TRANSACTION_PROPAGATE = $0020;
    TRANSACTION_SAVEPOINT = $0040;
    TRANSACTION_GENERIC_READ = (STANDARD_RIGHTS_READ Or TRANSACTION_QUERY_INFORMATION Or SYNCHRONIZE);
    TRANSACTION_GENERIC_WRITE = (STANDARD_RIGHTS_WRITE Or TRANSACTION_SET_INFORMATION Or TRANSACTION_COMMIT Or TRANSACTION_ENLIST Or TRANSACTION_ROLLBACK Or TRANSACTION_PROPAGATE Or TRANSACTION_SAVEPOINT Or SYNCHRONIZE);
    TRANSACTION_GENERIC_EXECUTE = (STANDARD_RIGHTS_EXECUTE Or TRANSACTION_COMMIT Or TRANSACTION_ROLLBACK Or SYNCHRONIZE);
    TRANSACTION_ALL_ACCESS= DWORD (STANDARD_RIGHTS_REQUIRED or TRANSACTION_GENERIC_READ or TRANSACTION_GENERIC_WRITE or TRANSACTION_GENERIC_EXECUTE);

    RTL_MAX_DRIVE_LETTERS =32;
    RTL_USER_PROC_PARAMS_NORMALIZED =    $00000001;

type
  PWSTR = PWideChar;

 {$ifdef CPU64}
  IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER64;
  PIMAGE_OPTIONAL_HEADER = PIMAGE_OPTIONAL_HEADER64;
{$else}
  IMAGE_OPTIONAL_HEADER = IMAGE_OPTIONAL_HEADER32;
  PIMAGE_OPTIONAL_HEADER = PIMAGE_OPTIONAL_HEADER32;
{$endif}
  TImageOptionalHeader = IMAGE_OPTIONAL_HEADER;
  PImageOptionalHeader = PIMAGE_OPTIONAL_HEADER;

  {$ifdef CPU64}
    IMAGE_NT_HEADERS = IMAGE_NT_HEADERS64;
    PIMAGE_NT_HEADERS = PIMAGE_NT_HEADERS64;
  {$else}
    IMAGE_NT_HEADERS = IMAGE_NT_HEADERS32;
    PIMAGE_NT_HEADERS = PIMAGE_NT_HEADERS32;
  {$endif}
    TImageNtHeaders = IMAGE_NT_HEADERS;
    PImageNtHeaders = PIMAGE_NT_HEADERS;

   PVOID = pointer;
   PPVOID = ^PVOID;
   NTSTATUS = ULONG;
   HANDLE = THANDLE;

 PUNICODE_STRING = ^UNICODE_STRING;
UNICODE_STRING = record
Length: Word;
MaximumLength: Word;
Buffer: PWideChar;
end;

POBJECT_ATTRIBUTES = ^OBJECT_ATTRIBUTES;
OBJECT_ATTRIBUTES = record
  Length: DWORD;
  RootDirectory: thandle;
  ObjectName: PUNICODE_STRING;
  Attributes: DWORD;
  SecurityDescriptor: Pointer;
  SecurityQualityOfService: Pointer;
end;
TObjectAttributes =OBJECT_ATTRIBUTES;

_CLIENT_ID = record
   UniqueProcess: uint64; //tHANDLE;
   UniqueThread: thandle; //tHANDLE;
 end;
 CLIENT_ID = _CLIENT_ID;
 PCLIENT_ID = ^CLIENT_ID;
 TClientID = CLIENT_ID;
 PClientID = ^TClientID;

 SECTION_INHERIT = ViewShare..ViewUnmap;

 PROCESS_BASIC_INFORMATION = record
      Reserved1:pvoid; //exit status?
      PebBaseAddress:pointer;
      Reserved2:array[0..1] of pvoid;     //affinity mask & base priority
      UniqueProcessId:ULONG_PTR;
      Reserved3:PVOID;
end;



 RTL_DRIVE_LETTER_CURDIR = record
	                  Flags:USHORT;
	                  Length:USHORT;
	                  TimeStamp:ULONG;
	                  DosPath:UNICODE_STRING;
 end;

 CURDIR = record
	 DosPath:UNICODE_STRING;
	 Handle:HANDLE;
end;

 RTL_USER_PROCESS_PARAMETERS=record

	 MaximumLength:ULONG;
	 Length:ULONG;

	 Flags:ULONG;
	 DebugFlags:ULONG;

	 ConsoleHandle:HANDLE;
	 ConsoleFlags:ULONG;
	 StandardInput:HANDLE;
	 StandardOutput:HANDLE;
	 StandardError:HANDLE;

	 CurrentDirectory:CURDIR;
	 DllPath:UNICODE_STRING;
	 ImagePathName:UNICODE_STRING;
	 CommandLine:UNICODE_STRING;
	 Environment:PVOID;

	 StartingX:ULONG;
	 StartingY:ULONG;
	 CountX:ULONG;
	 CountY:ULONG;
	 CountCharsX:ULONG;
	 CountCharsY:ULONG;
	 FillAttribute:ULONG;

	 WindowFlags:ULONG;
	 ShowWindowFlags:ULONG;
	 WindowTitle:UNICODE_STRING;
	 DesktopInfo:UNICODE_STRING;
	 ShellInfo:UNICODE_STRING;
	 RuntimeData:UNICODE_STRING;
	 CurrentDirectories:array [0..RTL_MAX_DRIVE_LETTERS-1] of RTL_DRIVE_LETTER_CURDIR;

	 EnvironmentSize:ULONG;
	 EnvironmentVersion:ULONG;
         PackageDependencyData:PVOID; //8+
         ProcessGroupId:ULONG;
         // ULONG LoaderThreads;
end;
 PRTL_USER_PROCESS_PARAMETERS=^RTL_USER_PROCESS_PARAMETERS;

 PEB =record
 	                 InheritedAddressSpace:BOOLEAN;
 	                 ReadImageFileExecOptions:BOOLEAN;
 	                 BeingDebugged:BOOLEAN;
 	                 Spare:BOOLEAN;
 	                 Mutant:HANDLE;
 	                 ImageBaseAddress:PVOID;
 	                 LoaderData:pvoid; //PPEB_LDR_DATA;
 	                 ProcessParameters:PRTL_USER_PROCESS_PARAMETERS;
 	                 SubSystemData:PVOID;
 	                 ProcessHeap:PVOID;
 	                 FastPebLock:PVOID;
 	                 FastPebLockRoutine:pvoid; //PPEBLOCKROUTINE;
 	                 FastPebUnlockRoutine:pvoid; //PPEBLOCKROUTINE;
 	                 EnvironmentUpdateCount:ULONG;
 	                 KernelCallbackTable:pvoid; //PVOID*;
 	                 EventLogSection:PVOID;
 	                 EventLog:PVOID;
 	                 FreeList:pvoid; //PPEB_FREE_BLOCK;
 	                 TlsExpansionCounter:ULONG;
 	                 TlsBitmap:PVOID;
 	                 TlsBitmapBits:array [0..1] of ULONG;
 	                 ReadOnlySharedMemoryBase:PVOID;
 	                 ReadOnlySharedMemoryHeap:PVOID;
 	                 ReadOnlyStaticServerData:pvoid; //PVOID*;
 	                 AnsiCodePageData:PVOID;
 	                 OemCodePageData:PVOID;
 	                 UnicodeCaseTableData:PVOID;
 	                 NumberOfProcessors:ULONG;
 	                 NtGlobalFlag:ULONG;
 	                 Spare2:array [0..3] of BYTE;
 	                 CriticalSectionTimeout:LARGE_INTEGER;
 	                   HeapSegmentReserve:ULONG;
 	                   HeapSegmentCommit:ULONG;
 	                   HeapDeCommitTotalFreeThreshold:ULONG;
 	                   HeapDeCommitFreeBlockThreshold:ULONG;
 	                   NumberOfHeaps:ULONG;
 	                   MaximumNumberOfHeaps:ULONG;
 	                  ProcessHeaps:pvoid; //PVOID*;
 	                   GdiSharedHandleTable:PVOID;
 	                   ProcessStarterHelper:PVOID;
 	                   GdiDCAttributeList:PVOID;
 	                   LoaderLock:PVOID;
 	                   OSMajorVersion:ULONG;
 	                   OSMinorVersion:ULONG;
 	                   OSBuildNumber:ULONG;
 	                   OSPlatformId:ULONG;
 	                   ImageSubSystem:ULONG;
 	                   ImageSubSystemMajorVersion:ULONG;
 	                   ImageSubSystemMinorVersion:ULONG;
 	                   GdiHandleBuffer:array [0..21] of ULONG;
 	                   PostProcessInitRoutine:ULONG;
 	                   TlsExpansionBitmap:ULONG;
 	                    TlsExpansionBitmapBits:array [0..79] of BYTE;
 	                   SessionId:ULONG;
 end;
 PPEB=^PEB;

 _IO_STATUS_BLOCK = record
    //union {
    Status: NTSTATUS;
    //    PVOID Pointer;
    //}
    Information: ULONG_PTR;
  end;
  IO_STATUS_BLOCK = _IO_STATUS_BLOCK;
  PIO_STATUS_BLOCK = ^IO_STATUS_BLOCK;
  TIoStatusBlock = IO_STATUS_BLOCK;
  PIoStatusBlock = ^TIoStatusBlock;

  _FILE_DISPOSITION_INFORMATION = record
  DeleteFile:BOOLEAN;
  end;
  FILE_DISPOSITION_INFORMATION=_FILE_DISPOSITION_INFORMATION;
  PFILE_DISPOSITION_INFORMATION=^FILE_DISPOSITION_INFORMATION;


   function NtSetInformationProcess(
      ProcessHandle:HANDLE;
      ProcessInformationClass:dword;
     ProcessInformation:pointer;
      ProcessInformationLength:ULONG
    ): NTSTATUS; stdcall; external 'ntdll.dll';

function  NtOpenProcess(
         ProcessHandle : PHANDLE;
         DesiredAccess : ACCESS_MASK;
         ObjectAttributes : POBJECT_ATTRIBUTES;
         ClientId : PCLIENT_ID
       ): NTSTATUS; stdcall; external 'ntdll.dll';

   function NtCreateSection(
          SectionHandle:PHANDLE;
          DesiredAccess:ACCESS_MASK;
          ObjectAttributes:POBJECT_ATTRIBUTES;
          MaximumSize:PLARGEINTEGER;
          SectionPageProtection:ULONG;
          AllocationAttributes:ULONG;
          FileHandle:HANDLE
          ): NTSTATUS; stdcall; external 'ntdll.dll';

   function  NtMapViewOfSection(
       SectionHandle : HANDLE;
       ProcessHandle : HANDLE;
       BaseAddress : PPVOID;
       ZeroBits : ULONG;
       CommitSize : ULONG;
       SectionOffset : PLARGE_INTEGER;
       ViewSize : PULONG;
       InheritDisposition : SECTION_INHERIT;
       AllocationType : ULONG;
       Protect : ULONG
     ): NTSTATUS; stdcall; external 'ntdll.dll';

   function NtCreateTransaction(
      TransactionHandle:PHANDLE;
      DesiredAccess: ACCESS_MASK;
      ObjectAttributes: Pointer;
      Uow:LPGUID;
      TmHandle: THANDLE;
      CreateOptions:ULONG;
      IsolationLevel:ULONG;
      IsolationFlags:ULONG;
      Timeout:PLARGE_INTEGER;
      Description:PUNICODE_STRING
   ): NTSTATUS; stdcall;  external 'ntdll.dll';

   function NtRollbackTransaction(TransactionHandle:HANDLE;flag:boolean): NTSTATUS;  stdcall; external 'ntdll.dll';

   function  NtSetInformationFile(
       FileHandle : HANDLE;
       IoStatusBlock : PIO_STATUS_BLOCK;
       FileInformation : PVOID;
       FileInformationLength : ULONG;
       FileInformationClass : dword //FILE_INFORMATION_CLASS
     ): NTSTATUS; stdcall;  external 'ntdll.dll';

   function NtCreateThreadEx(
     ThreadHandle:PHANDLE;
     DesiredAccess: ACCESS_MASK;
     ObjectAttributes: Pointer;
     ProcessHandle: THANDLE;
     lpStartAddress: Pointer;
     lpParameter: Pointer;
     CreateSuspended: BOOL;
     dwStackSize: DWORD;
     SizeOfStackCommit: Pointer;
     SizeOfStackReserve: Pointer;
     Thebuf: Pointer): HRESULT; stdcall; external 'ntdll.dll';

    function NtCreateProcessEx(
       ProcessHandle:PHANDLE;
       DesiredAccess:ACCESS_MASK;
       ObjectAttributes: Pointer;
       ParentProcess:THANDLE;
       Flags:ULONG;
       SectionHandle: THANDLE;
       DebugPort: THANDLE;
       ExceptionPort: THANDLE;
       InJob:BOOLEAN
   ): NTSTATUS; stdcall; stdcall; external 'ntdll.dll';

   function  NtClose(Handle : HANDLE): NTSTATUS; stdcall; external 'ntdll.dll';

   function  NtQueryInformationProcess(
  ProcessHandle : THandle;
  ProcessInformationClass : DWORD;
  ProcessInformation : Pointer;
  ProcessInformationLength : ULONG;
  ReturnLength : PULONG
 ): LongInt; stdcall; external 'ntdll.dll';

   function NtReadVirtualMemory(
     ProcessHandle:HANDLE; //IN HANDLE
     BaseAddress:PVOID; //IN PVOID
     Buffer:PVOID; //OUT PVOID
     NumberOfBytesToRead:ULONG; //IN ULONG
     NumberOfBytesReaded:PULONG): NTSTATUS; stdcall; external 'ntdll.dll';

   function NtAllocateVirtualMemory(
         ProcessHandle : HANDLE;
         BaseAddress : PPVOID;
         ZeroBits : ULONG;
         AllocationSize : PULONG;
         AllocationType : ULONG;
         Protect : ULONG
       ): NTSTATUS; stdcall; external 'ntdll.dll';

   function NtWriteVirtualMemory(
         ProcessHandle : HANDLE;
         BaseAddress : PVOID;
         Buffer : PVOID;
         BufferLength : ULONG;
         ReturnLength : PULONG): NTSTATUS; stdcall; external 'ntdll.dll';

   function RtlImageNtHeader(ModuleAddress:PVOID):PIMAGE_NT_HEADERS; stdcall; external 'ntdll.dll';

   function RtlCreateProcessParametersEx(
         pProcessParameters:PPVOID; //pointer to PRTL_USER_PROCESS_PARAMETERS;
         ImagePathName:PUNICODE_STRING;
         DllPath:PUNICODE_STRING;
         CurrentDirectory:PUNICODE_STRING;
         CommandLine:PUNICODE_STRING;
         Environment:PVOID;
         WindowTitle:PUNICODE_STRING;
         DesktopInfo:PUNICODE_STRING;
         ShellInfo:PUNICODE_STRING;
         RuntimeData:PUNICODE_STRING;
         Flags:ULONG // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
   ): NTSTATUS; stdcall; external 'ntdll.dll';

   function RtlDestroyProcessParameters(pProcessParameters:PVOID): NTSTATUS; stdcall; external 'ntdll.dll';

      procedure RtlInitUnicodeString(DestinationString: PUNICODE_STRING; SourceString: PWSTR); stdcall; external 'ntdll.dll';

      //https://www.unknowncheats.me/forum/c-and-c-/119210-xp-sp2-privileged-dll-injection.html
      {
      function CsrClientCallServer(
      ApiMessage:pointer; //IN OUT CSR_API_MESSAGE*
      CaptureBuffer:pointer; //IN OUT struct CSR_CAPTURE_BUFFER*
      ApiNumber:ULONG;
      DataLength:ULONG ): NTSTATUS; stdcall; external 'ntdll.dll';
      }

implementation

end.

