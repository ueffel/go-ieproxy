package ieproxy

import "C" // Needed so the WinHttpSetStatusCallback can actually be called. See https://github.com/golang/go/issues/10973

import (
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (psc *ProxyScriptConf) findProxyForURL(URL string) string {
	if !psc.Active {
		return ""
	}
	scheme, proxy, port, err := getProxyForURLEx(psc.PreConfiguredURL, URL)
	if err != nil {
		return ""
	}
	switch scheme {
	case 1:
		return fmt.Sprint("http://", proxy, ":", port)
	case 2:
		return fmt.Sprint("https://", proxy, ":", port)
	case 4:
		// SOCKS4 proxy.ip:port
		if strings.HasPrefix(proxy, "4 ") {
			// not supported
			return ""
		}
		proxy = strings.TrimPrefix(proxy, "5 ") // SOCKS5 proxy.ip:port
		return fmt.Sprint("socks5://", proxy, ":", port)
	default:
		return ""
	}
}

func StatusCallback(
	hInternet uintptr,
	dwContext *sync.WaitGroup,
	dwInternetStatus uint32,
	lpvStatusInformation uintptr,
	dwStatusInformationLength uint32,
) uintptr {
	dwContext.Done()
	return 0
}

func getProxyForURLEx(pacfileURL, URL string) (uint16, string, uint16, error) {
	pacfileURLPtr, err := syscall.UTF16PtrFromString(pacfileURL)
	if err != nil {
		return 0, "", 0, err
	}
	URLPtr, err := syscall.UTF16PtrFromString(URL)
	if err != nil {
		return 0, "", 0, err
	}

	handle, _, err := winHttpOpen.Call(0, 0, 0, 0, uintptr(fWINHTTP_FLAG_ASYNC))
	if handle == 0 {
		return 0, "", 0, err
	}
	defer winHttpCloseHandle.Call(handle)

	cb := syscall.NewCallback(StatusCallback)
	ret, _, err := winHttpSetStatusCallback.Call(
		handle,
		cb,
		uintptr(fWINHTTP_CALLBACK_FLAG_REQUEST_ERROR|fWINHTTP_CALLBACK_FLAG_GETPROXYFORURL_COMPLETE),
		0)
	if ret != 0 {
		return 0, "", 0, err
	}

	resolver := uintptr(0)
	ret, _, err = winHttpCreateProxyResolver.Call(handle, uintptr(unsafe.Pointer(&resolver)))
	if ret != 0 {
		return 0, "", 0, err
	}
	defer winHttpCloseHandle.Call(resolver)

	dwFlags := fWINHTTP_AUTOPROXY_CONFIG_URL
	dwAutoDetectFlags := autoDetectFlag(0)
	pfURLptr := pacfileURLPtr

	if pacfileURL == "" {
		dwFlags = fWINHTTP_AUTOPROXY_AUTO_DETECT
		dwAutoDetectFlags = fWINHTTP_AUTO_DETECT_TYPE_DNS_A | fWINHTTP_AUTO_DETECT_TYPE_DHCP
		pfURLptr = nil
	}

	options := tWINHTTP_AUTOPROXY_OPTIONS{
		dwFlags:                dwFlags, // adding cache might cause issues: https://github.com/mattn/go-ieproxy/issues/6
		dwAutoDetectFlags:      dwAutoDetectFlags,
		lpszAutoConfigUrl:      pfURLptr,
		lpvReserved:            nil,
		dwReserved:             0,
		fAutoLogonIfChallenged: true, // may not be optimal https://msdn.microsoft.com/en-us/library/windows/desktop/aa383153(v=vs.85).aspx
	} // lpszProxyBypass isn't used as this only executes in cases where there (may) be a pac file (autodetect can fail), where lpszProxyBypass couldn't be returned.
	// in the case that autodetect fails and no pre-specified pacfile is present, no proxy is returned.

	wait := &sync.WaitGroup{}
	wait.Add(1)
	ret, _, err = winHttpGetProxyForURLEx.Call(
		resolver,
		uintptr(unsafe.Pointer(URLPtr)),
		uintptr(unsafe.Pointer(&options)),
		uintptr(unsafe.Pointer(wait)))
	if ret != uintptr(windows.ERROR_IO_PENDING) {
		return 0, "", 0, err
	}
	wait.Wait()

	proxyResult := &tWINHTTP_PROXY_RESULT{}
	ret, _, err = winHttpGetProxyResult.Call(resolver, uintptr(unsafe.Pointer(proxyResult)))
	if ret != 0 {
		return 0, "", 0, err
	}
	defer winHttpFreeProxyResult.Call(uintptr(unsafe.Pointer(proxyResult)))

	entries := unsafe.Slice(proxyResult.pEntries, proxyResult.cEntries)
	if len(entries) > 0 && entries[0].fProxy {
		return entries[0].ProxyScheme, StringFromUTF16Ptr(entries[0].pwszProxy), entries[0].ProxyPort, nil
	}

	return 0, "", 0, err
}
