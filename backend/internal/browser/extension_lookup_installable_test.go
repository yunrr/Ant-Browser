package browser

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// stubRoundTripper 拦截所有请求，让下载逻辑不依赖真实网络。
type stubRoundTripper struct {
	status int
	body   string
	err    error
}

func (s stubRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if s.err != nil {
		return nil, s.err
	}
	status := s.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Request:    request,
	}, nil
}

// 拿不到安装包时不能报「可安装」：否则界面上「可安装」后面紧跟一次必然失败的
// 安装，用户看到的是二次报错（插件包不是有效的 CRX/ZIP 文件），真正原因被盖住。
func TestLookupExtensionMarksUnavailableWhenStoreReturnsNoContent(t *testing.T) {
	manager := newIsolationManager(t)
	client := &http.Client{Transport: stubRoundTripper{status: http.StatusNoContent}}

	result, err := manager.LookupExtensionWithHTTPClient("aeblfdkhhhdcdjpifhhbdiojplfjncoa", client)
	if err != nil {
		t.Fatalf("LookupExtensionWithHTTPClient returned error: %v", err)
	}
	if result.Installable {
		t.Fatal("Installable = true for HTTP 204, want false")
	}
	if !strings.Contains(result.Message, "204") {
		t.Fatalf("Message = %q, want it to explain the 204 response", result.Message)
	}
}

// 下载直接失败（网络不通、商店 5xx）同样是「不可安装」，不能只把原因塞进 Message。
func TestLookupExtensionMarksUnavailableWhenDownloadFails(t *testing.T) {
	manager := newIsolationManager(t)
	client := &http.Client{Transport: stubRoundTripper{err: errors.New("boom")}}

	result, err := manager.LookupExtensionWithHTTPClient("aeblfdkhhhdcdjpifhhbdiojplfjncoa", client)
	if err != nil {
		t.Fatalf("LookupExtensionWithHTTPClient returned error: %v", err)
	}
	if result.Installable {
		t.Fatal("Installable = true when download failed, want false")
	}
	if result.ExtensionID != "aeblfdkhhhdcdjpifhhbdiojplfjncoa" {
		t.Fatalf("ExtensionID = %q, want it preserved so the user can retry", result.ExtensionID)
	}
}
