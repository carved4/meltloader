package pe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unsafe"

	wc "github.com/carved4/go-wincall"
)

const (
	memCommit        = 0x00001000
	memReserve       = 0x00002000
	memRelease       = 0x00008000
	pageRW           = 0x04
	pageR            = 0x02
	pageRX           = 0x20
	pageRWX          = 0x40
	th32SnapModule   = 0x00000008
	th32SnapModule32 = 0x00000010
)

type moduleEntry32 struct {
	dwSize        uint32
	th32ModuleID  uint32
	th32ProcessID uint32
	glblcntUsage  uint32
	proccntUsage  uint32
	modBaseAddr   uintptr
	modBaseSize   uint32
	hModule       uintptr
	szModule      [256]uint16
	szExePath     [260]uint16
}

func LoadDLLRemote(hProcess uintptr, dllBytes []byte) (uintptr, error) {
	if len(dllBytes) < 64 || dllBytes[0] != 'M' || dllBytes[1] != 'Z' {
		return 0, errors.New("invalid PE")
	}

	peOffset := *(*uint32)(unsafe.Pointer(&dllBytes[60]))
	peHeaderAddr := uintptr(unsafe.Pointer(&dllBytes[peOffset]))
	optHeaderAddr := peHeaderAddr + 0x18
	sizeOfImage := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x38))
	sizeOfHeaders := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x3C))
	preferredBase := *(*uint64)(unsafe.Pointer(optHeaderAddr + 0x18))

	ntAlloc := wc.GetSyscall(wc.GetHash("NtAllocateVirtualMemory"))
	var remoteBase uintptr
	var regionSize uintptr = uintptr(sizeOfImage)

	ret, _ := wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address,
		hProcess, uintptr(unsafe.Pointer(&remoteBase)), 0,
		uintptr(unsafe.Pointer(&regionSize)), memCommit|memReserve, pageRW)
	if ret != 0 || remoteBase == 0 {
		return 0, errors.New("NtAllocateVirtualMemory failed")
	}

	ntWrite := wc.GetSyscall(wc.GetHash("NtWriteVirtualMemory"))
	var written uintptr
	ret, _ = wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
		hProcess, remoteBase, uintptr(unsafe.Pointer(&dllBytes[0])),
		uintptr(sizeOfHeaders), uintptr(unsafe.Pointer(&written)))
	if ret != 0 {
		return 0, errors.New("NtWriteVirtualMemory failed")
	}

	numSections := *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x06))
	sizeOfOptHeader := *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x14))

	for i := uint16(0); i < numSections; i++ {
		sectionHeader := uintptr(unsafe.Pointer(&dllBytes[0])) + uintptr(peOffset) + 0x18 + uintptr(sizeOfOptHeader) + uintptr(i*40)
		virtualAddress := *(*uint32)(unsafe.Pointer(sectionHeader + 0x0C))
		sizeOfRawData := *(*uint32)(unsafe.Pointer(sectionHeader + 0x10))
		pointerToRawData := *(*uint32)(unsafe.Pointer(sectionHeader + 0x14))

		if sizeOfRawData == 0 {
			continue
		}

		ret, _ = wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
			hProcess, remoteBase+uintptr(virtualAddress),
			uintptr(unsafe.Pointer(&dllBytes[pointerToRawData])),
			uintptr(sizeOfRawData), uintptr(unsafe.Pointer(&written)))
		if ret != 0 {
			return 0, errors.New("NtWriteVirtualMemory section failed")
		}
	}

	delta := int64(remoteBase) - int64(preferredBase)
	if delta != 0 {
		relocDirRVA := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x70 + (5 * 8)))
		relocDirSize := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x70 + (5 * 8) + 4))
		if relocDirRVA != 0 && relocDirSize != 0 {
			processRelocations(hProcess, remoteBase, &dllBytes, relocDirRVA, relocDirSize, delta)
		}
	}

	importDirRVA := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x70 + (1 * 8)))
	if importDirRVA != 0 {
		pid, _ := getProcessId(hProcess)
		resolveImports(hProcess, pid, remoteBase, &dllBytes, importDirRVA)
	}

	ntProt := wc.GetSyscall(wc.GetHash("NtProtectVirtualMemory"))
	for i := uint16(0); i < numSections; i++ {
		sectionHeader := uintptr(unsafe.Pointer(&dllBytes[0])) + uintptr(peOffset) + 0x18 + uintptr(sizeOfOptHeader) + uintptr(i*40)
		virtualSize := *(*uint32)(unsafe.Pointer(sectionHeader + 0x08))
		virtualAddress := *(*uint32)(unsafe.Pointer(sectionHeader + 0x0C))
		characteristics := *(*uint32)(unsafe.Pointer(sectionHeader + 0x24))

		if virtualSize == 0 {
			continue
		}

		var prot uint32 = pageR
		if (characteristics & 0x20000000) != 0 {
			if (characteristics & 0x80000000) != 0 {
				prot = pageRWX
			} else {
				prot = pageRX
			}
		} else if (characteristics & 0x80000000) != 0 {
			prot = pageRW
		}

		var oldProt uint32
		baseAddr := remoteBase + uintptr(virtualAddress)
		regionSz := uintptr(virtualSize)
		wc.IndirectSyscall(ntProt.SSN, ntProt.Address, hProcess,
			uintptr(unsafe.Pointer(&baseAddr)), uintptr(unsafe.Pointer(&regionSz)),
			uintptr(prot), uintptr(unsafe.Pointer(&oldProt)))
	}

	entryPointRVA := *(*uint32)(unsafe.Pointer(optHeaderAddr + 0x10))
	if entryPointRVA != 0 {
		callDllMain(hProcess, remoteBase, remoteBase+uintptr(entryPointRVA))
	}

	return remoteBase, nil
}

func MeltRemote(hProcess uintptr, remoteBase uintptr) error {
	if remoteBase == 0 {
		return errors.New("nil remote base address")
	}

	ntFree := wc.GetSyscall(wc.GetHash("NtFreeVirtualMemory"))
	var baseAddr uintptr = remoteBase
	var regionSize uintptr = 0

	ret, _ := wc.IndirectSyscall(ntFree.SSN, ntFree.Address,
		hProcess,
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		memRelease)
	if ret != 0 {
		return fmt.Errorf("NtFreeVirtualMemory failed: 0x%x", ret)
	}

	return nil
}

func uintptrToBytes(ptr uintptr) []byte {
	ptrPtr := unsafe.Pointer(&ptr)

	byteSlice := make([]byte, unsafe.Sizeof(ptr))
	for i := 0; i < int(unsafe.Sizeof(ptr)); i++ {
		byteSlice[i] = *(*byte)(unsafe.Pointer(uintptr(ptrPtr) + uintptr(i)))
	}

	return byteSlice
}
func processRelocations(hProcess uintptr, remoteBase uintptr, dllBytes *[]byte, relocDirRVA, relocDirSize uint32, delta int64) {
	ntRead := wc.GetSyscall(wc.GetHash("NtReadVirtualMemory"))
	ntWrite := wc.GetSyscall(wc.GetHash("NtWriteVirtualMemory"))

	localBase := uintptr(unsafe.Pointer(&(*dllBytes)[0]))
	relocOffset := rvaToOffset(dllBytes, relocDirRVA)
	relocDir := localBase + uintptr(relocOffset)
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

			patchAddr := remoteBase + uintptr(pageRVA) + uintptr(offset)

			if relocType == 10 {
				var buf [8]byte
				var bytesRead uintptr
				ret, _ := wc.IndirectSyscall(ntRead.SSN, ntRead.Address,
					hProcess, patchAddr, uintptr(unsafe.Pointer(&buf[0])), 8, uintptr(unsafe.Pointer(&bytesRead)))
				if ret != 0 {
					continue
				}
				oldValue := binary.LittleEndian.Uint64(buf[:])
				binary.LittleEndian.PutUint64(buf[:], uint64(int64(oldValue)+delta))
				var written uintptr
				wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
					hProcess, patchAddr, uintptr(unsafe.Pointer(&buf[0])), 8, uintptr(unsafe.Pointer(&written)))
			} else if relocType == 3 {
				var buf [4]byte
				var bytesRead uintptr
				ret, _ := wc.IndirectSyscall(ntRead.SSN, ntRead.Address,
					hProcess, patchAddr, uintptr(unsafe.Pointer(&buf[0])), 4, uintptr(unsafe.Pointer(&bytesRead)))
				if ret != 0 {
					continue
				}
				oldValue := binary.LittleEndian.Uint32(buf[:])
				binary.LittleEndian.PutUint32(buf[:], uint32(int32(oldValue)+int32(delta)))
				var written uintptr
				wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
					hProcess, patchAddr, uintptr(unsafe.Pointer(&buf[0])), 4, uintptr(unsafe.Pointer(&written)))
			}
		}
		relocDir += uintptr(blockSize)
	}
}

func resolveImports(hProcess uintptr, pid uint32, remoteBase uintptr, dllBytes *[]byte, importDirRVA uint32) {
	ntWrite := wc.GetSyscall(wc.GetHash("NtWriteVirtualMemory"))
	localBase := uintptr(unsafe.Pointer(&(*dllBytes)[0]))
	importDescOffset := rvaToOffset(dllBytes, importDirRVA)
	importDesc := localBase + uintptr(importDescOffset)

	for {
		originalFirstThunk := *(*uint32)(unsafe.Pointer(importDesc + 0x00))
		nameRVA := *(*uint32)(unsafe.Pointer(importDesc + 0x0C))
		firstThunk := *(*uint32)(unsafe.Pointer(importDesc + 0x10))

		if nameRVA == 0 {
			break
		}

		nameOffset := rvaToOffset(dllBytes, nameRVA)
		dllName := cstringAt(localBase + uintptr(nameOffset))

		actualDllName := dllName
		if isApiSet(dllName) {
			if resolved := resolveApiSet(dllName); resolved != "" {
				actualDllName = resolved
			}
		}

		localModule := wc.LoadLibraryLdr(actualDllName)
		if localModule == 0 {
			importDesc += 20
			continue
		}

		remoteModule, _ := getRemoteModuleBase(pid, actualDllName)
		if remoteModule == 0 {
			remoteModule, _ = loadLibraryRemote(hProcess, pid, actualDllName)
			if remoteModule == 0 {
				importDesc += 20
				continue
			}
		}

		thunkRVA := originalFirstThunk
		if thunkRVA == 0 {
			thunkRVA = firstThunk
		}

		thunkOffset := rvaToOffset(dllBytes, thunkRVA)
		thunkAddr := localBase + uintptr(thunkOffset)
		iatRemote := remoteBase + uintptr(firstThunk)

		for {
			thunkValue := *(*uint64)(unsafe.Pointer(thunkAddr))
			if thunkValue == 0 {
				break
			}

			var funcRVA uintptr
			if (thunkValue & 0x8000000000000000) != 0 {
				ordinal := uint16(thunkValue & 0xFFFF)
				localFunc, _, _ := wc.Call("kernel32.dll", "GetProcAddress", localModule, uintptr(ordinal))
				if localFunc != 0 {
					funcRVA = localFunc - localModule
				}
			} else {
				importByNameOffset := rvaToOffset(dllBytes, uint32(thunkValue))
				funcName := cstringAt(localBase + uintptr(importByNameOffset) + 2)
				localFunc := wc.GetFunctionAddress(localModule, wc.GetHash(funcName))
				if localFunc != 0 {
					funcRVA = localFunc - localModule
				}
			}

			if funcRVA != 0 {
				var buf [8]byte
				binary.LittleEndian.PutUint64(buf[:], uint64(remoteModule+funcRVA))
				var written uintptr
				wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
					hProcess, iatRemote, uintptr(unsafe.Pointer(&buf[0])), 8, uintptr(unsafe.Pointer(&written)))
			}

			thunkAddr += 8
			iatRemote += 8
		}
		importDesc += 20
	}
}

func callDllMain(hProcess uintptr, dllBase uintptr, entryPoint uintptr) {
	// stub to call dllMain :3
	code := make([]byte, 0, 48)
	code = append(code, 0x48, 0xB9)
	code = append(code, uintptrToBytes(dllBase)...)
	code = append(code, 0xBA, 0x01, 0x00, 0x00, 0x00)
	code = append(code, 0x4D, 0x31, 0xC0)
	code = append(code, 0x48, 0xB8)
	code = append(code, uintptrToBytes(entryPoint)...)
	code = append(code, 0x48, 0x83, 0xEC, 0x28)
	code = append(code, 0xFF, 0xD0)
	code = append(code, 0x48, 0x83, 0xC4, 0x28)
	code = append(code, 0xC3)

	ntAlloc := wc.GetSyscall(wc.GetHash("NtAllocateVirtualMemory"))
	var stubAddr uintptr
	var stubSize uintptr = uintptr(len(code))
	wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address,
		hProcess, uintptr(unsafe.Pointer(&stubAddr)), 0,
		uintptr(unsafe.Pointer(&stubSize)), memCommit|memReserve, pageRWX)

	ntWrite := wc.GetSyscall(wc.GetHash("NtWriteVirtualMemory"))
	var written uintptr
	wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
		hProcess, stubAddr, uintptr(unsafe.Pointer(&code[0])), uintptr(len(code)), uintptr(unsafe.Pointer(&written)))

	hThread, _, _ := wc.Call("kernel32.dll", "CreateRemoteThread", hProcess, 0, 0, stubAddr, 0, 0, 0)
	if hThread != 0 {
		wc.Call("kernel32.dll", "WaitForSingleObject", hThread, 10000)
		wc.Call("kernel32.dll", "CloseHandle", hThread)
	}

	ntFree := wc.GetSyscall(wc.GetHash("NtFreeVirtualMemory"))
	stubSize = 0
	wc.IndirectSyscall(ntFree.SSN, ntFree.Address, hProcess, uintptr(unsafe.Pointer(&stubAddr)), uintptr(unsafe.Pointer(&stubSize)), memRelease)
}

func loadLibraryRemote(hProcess uintptr, pid uint32, moduleName string) (uintptr, error) {
	nameBytes := append([]byte(moduleName), 0)
	size := uintptr(len(nameBytes))

	ntAlloc := wc.GetSyscall(wc.GetHash("NtAllocateVirtualMemory"))
	var remoteBuf uintptr
	var regionSize uintptr = size
	ret, _ := wc.IndirectSyscall(ntAlloc.SSN, ntAlloc.Address,
		hProcess, uintptr(unsafe.Pointer(&remoteBuf)), 0, uintptr(unsafe.Pointer(&regionSize)), memCommit|memReserve, pageRW)
	if ret != 0 || remoteBuf == 0 {
		return 0, errors.New("alloc failed")
	}

	ntWrite := wc.GetSyscall(wc.GetHash("NtWriteVirtualMemory"))
	var written uintptr
	wc.IndirectSyscall(ntWrite.SSN, ntWrite.Address,
		hProcess, remoteBuf, uintptr(unsafe.Pointer(&nameBytes[0])), size, uintptr(unsafe.Pointer(&written)))

	k32 := wc.GetModuleBase(wc.GetHash("kernel32.dll"))
	loadLibA := wc.GetFunctionAddress(k32, wc.GetHash("LoadLibraryA"))

	hThread, _, _ := wc.Call("kernel32.dll", "CreateRemoteThread", hProcess, 0, 0, loadLibA, remoteBuf, 0, 0)
	if hThread != 0 {
		wc.Call("kernel32.dll", "WaitForSingleObject", hThread, 0xFFFFFFFF)
		wc.Call("kernel32.dll", "CloseHandle", hThread)
	}

	ntFree := wc.GetSyscall(wc.GetHash("NtFreeVirtualMemory"))
	regionSize = 0
	wc.IndirectSyscall(ntFree.SSN, ntFree.Address, hProcess, uintptr(unsafe.Pointer(&remoteBuf)), uintptr(unsafe.Pointer(&regionSize)), memRelease)

	return getRemoteModuleBase(pid, moduleName)
}

func getRemoteModuleBase(pid uint32, moduleName string) (uintptr, error) {
	snap, _, _ := wc.Call("kernel32.dll", "CreateToolhelp32Snapshot", th32SnapModule|th32SnapModule32, uintptr(pid))
	if snap == 0 || snap == ^uintptr(0) {
		return 0, errors.New("snapshot failed")
	}
	defer wc.Call("kernel32.dll", "CloseHandle", snap)

	var me moduleEntry32
	me.dwSize = uint32(unsafe.Sizeof(me))

	ok, _, _ := wc.Call("kernel32.dll", "Module32FirstW", snap, uintptr(unsafe.Pointer(&me)))
	if ok == 0 {
		return 0, errors.New("Module32FirstW failed")
	}

	target := strings.ToLower(moduleName)
	for {
		name := strings.ToLower(utf16ToString(me.szModule[:]))
		if name == target {
			return me.modBaseAddr, nil
		}
		ok, _, _ = wc.Call("kernel32.dll", "Module32NextW", snap, uintptr(unsafe.Pointer(&me)))
		if ok == 0 {
			break
		}
	}
	return 0, errors.New("module not found")
}

func getProcessId(hProcess uintptr) (uint32, error) {
	pid, _, _ := wc.Call("kernel32.dll", "GetProcessId", hProcess)
	return uint32(pid), nil
}

func utf16ToString(buf []uint16) string {
	n := 0
	for n < len(buf) && buf[n] != 0 {
		n++
	}
	return string(utf16.Decode(buf[:n]))
}

func resolveApiSet(name string) string {
	n := strings.ToLower(name)
	if strings.HasPrefix(n, "api-ms-win-crt-") {
		return "ucrtbase.dll"
	}
	if strings.HasPrefix(n, "api-ms-win-core-") {
		return "kernelbase.dll"
	}
	if strings.HasPrefix(n, "ext-ms-") {
		return "kernelbase.dll"
	}
	if strings.HasPrefix(n, "api-ms-win-security-") || strings.HasPrefix(n, "api-ms-win-eventing-") {
		return "advapi32.dll"
	}
	return ""
}

func isApiSet(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "api-ms-") || strings.HasPrefix(n, "ext-ms-")
}

func cstringAt(addr uintptr) string {
	var bs []byte
	for i := uintptr(0); ; i++ {
		b := *(*byte)(unsafe.Pointer(addr + i))
		if b == 0 {
			break
		}
		bs = append(bs, b)
	}
	return string(bs)
}

func rvaToOffset(dllBytes *[]byte, rva uint32) uint32 {
	localBase := uintptr(unsafe.Pointer(&(*dllBytes)[0]))
	peOffset := *(*uint32)(unsafe.Pointer(localBase + 60))
	peHeaderAddr := localBase + uintptr(peOffset)
	numSections := *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x06))
	sizeOfOptHeader := *(*uint16)(unsafe.Pointer(peHeaderAddr + 0x14))
	sectionHeaderAddr := peHeaderAddr + 0x18 + uintptr(sizeOfOptHeader)

	for i := uint16(0); i < numSections; i++ {
		sectionHeader := sectionHeaderAddr + uintptr(i*40)
		virtualSize := *(*uint32)(unsafe.Pointer(sectionHeader + 0x08))
		virtualAddress := *(*uint32)(unsafe.Pointer(sectionHeader + 0x0C))
		pointerToRawData := *(*uint32)(unsafe.Pointer(sectionHeader + 0x14))

		if rva >= virtualAddress && rva < virtualAddress+virtualSize {
			return pointerToRawData + (rva - virtualAddress)
		}
	}
	return rva
}
