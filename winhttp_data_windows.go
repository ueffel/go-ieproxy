package ieproxy

import "golang.org/x/sys/windows"

var (
	winHttp                               = windows.NewLazySystemDLL("winhttp.dll")
	winHttpOpen                           = winHttp.NewProc("WinHttpOpen")
	winHttpCloseHandle                    = winHttp.NewProc("WinHttpCloseHandle")
	winHttpGetIEProxyConfigForCurrentUser = winHttp.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	winHttpGetDefaultProxyConfiguration   = winHttp.NewProc("WinHttpGetDefaultProxyConfiguration")
	winHttpGetProxyForURLEx               = winHttp.NewProc("WinHttpGetProxyForUrlEx")
	winHttpSetStatusCallback              = winHttp.NewProc("WinHttpSetStatusCallback")
	winHttpCreateProxyResolver            = winHttp.NewProc("WinHttpCreateProxyResolver")
	winHttpGetProxyResult                 = winHttp.NewProc("WinHttpGetProxyResult")
	winHttpFreeProxyResult                = winHttp.NewProc("WinHttpFreeProxyResult")
)

type tWINHTTP_AUTOPROXY_OPTIONS struct {
	dwFlags                autoProxyFlag
	dwAutoDetectFlags      autoDetectFlag
	lpszAutoConfigUrl      *uint16
	lpvReserved            *uint16
	dwReserved             uint32
	fAutoLogonIfChallenged bool
}
type autoProxyFlag uint32

const (
	fWINHTTP_AUTOPROXY_AUTO_DETECT         = autoProxyFlag(0x00000001)
	fWINHTTP_AUTOPROXY_CONFIG_URL          = autoProxyFlag(0x00000002)
	fWINHTTP_AUTOPROXY_NO_CACHE_CLIENT     = autoProxyFlag(0x00080000)
	fWINHTTP_AUTOPROXY_NO_CACHE_SVC        = autoProxyFlag(0x00100000)
	fWINHTTP_AUTOPROXY_NO_DIRECTACCESS     = autoProxyFlag(0x00040000)
	fWINHTTP_AUTOPROXY_RUN_INPROCESS       = autoProxyFlag(0x00010000)
	fWINHTTP_AUTOPROXY_RUN_OUTPROCESS_ONLY = autoProxyFlag(0x00020000)
	fWINHTTP_AUTOPROXY_SORT_RESULTS        = autoProxyFlag(0x00400000)
)

const (
	fWINHTTP_FLAG_ASYNC                            = uint32(0x10000000)
	fWINHTTP_CALLBACK_FLAG_REQUEST_ERROR           = uint32(0x00200000)
	fWINHTTP_CALLBACK_FLAG_GETPROXYFORURL_COMPLETE = uint32(0x01000000)
)

type autoDetectFlag uint32

const (
	fWINHTTP_AUTO_DETECT_TYPE_DHCP  = autoDetectFlag(0x00000001)
	fWINHTTP_AUTO_DETECT_TYPE_DNS_A = autoDetectFlag(0x00000002)
)

type tWINHTTP_PROXY_INFO struct {
	dwAccessType    uint32
	lpszProxy       *uint16
	lpszProxyBypass *uint16
}

type tWINHTTP_CURRENT_USER_IE_PROXY_CONFIG struct {
	fAutoDetect       bool
	lpszAutoConfigUrl *uint16
	lpszProxy         *uint16
	lpszProxyBypass   *uint16
}

type tWINHTTP_PROXY_RESULT struct {
	cEntries uint32
	pEntries *tWINHTTP_PROXY_RESULT_ENTRY
}

type tWINHTTP_PROXY_RESULT_ENTRY struct {
	fProxy      bool
	_           [3]byte // Padding so struct alignment is correct
	fByPass     bool
	_           [3]byte // Padding so struct alignment is correct
	ProxyScheme uint16
	pwszProxy   *uint16
	ProxyPort   uint16
}
