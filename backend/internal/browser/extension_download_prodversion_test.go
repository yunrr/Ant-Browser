package browser

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 下载地址必须带上真实内核版本：写死低版本时，要求更高 Chrome 的插件
// 会拿到 204 空响应，表现成「插件包不是有效的 CRX/ZIP 文件」。
func TestBuildChromeExtensionDownloadURLUsesProdVersion(t *testing.T) {
	const extensionID = "aeblfdkhhhdcdjpifhhbdiojplfjncoa"

	url := BuildChromeExtensionDownloadURLWithProdVersion(extensionID, "148.0.7778.215")
	if !strings.Contains(url, "prodversion=148.0.7778.215") {
		t.Fatalf("download URL = %q, want prodversion=148.0.7778.215", url)
	}
	if !strings.Contains(url, "response=redirect") || !strings.Contains(url, "acceptformat=crx2,crx3") {
		t.Fatalf("download URL = %q, want redirect + crx2,crx3", url)
	}
	if !strings.Contains(url, "id%3D"+extensionID) {
		t.Fatalf("download URL = %q, want extension id %q", url, extensionID)
	}

	// 空版本要回落到足够高的兜底值，不能退化成 0 或空串。
	fallback := BuildChromeExtensionDownloadURLWithProdVersion(extensionID, "")
	if !strings.Contains(fallback, "prodversion="+extensionDownloadFallbackProdVersion) {
		t.Fatalf("fallback URL = %q, want prodversion=%s", fallback, extensionDownloadFallbackProdVersion)
	}
}

// 204 是商店「按该版本不提供安装包」的正常应答，必须报成版本不匹配，
// 不能落进 2xx 成功分支后只报「插件包不是有效的 CRX/ZIP 文件」。
func TestDownloadChromeExtensionCRXTreatsNoContentAsVersionMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("prodversion"); got != "148.0.7778.215" {
			t.Errorf("prodversion = %q, want 148.0.7778.215", got)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	_, err := downloadChromeExtensionCRXOnce(context.Background(), server.Client(), server.URL+"/crx?prodversion=148.0.7778.215", "148.0.7778.215")
	if err == nil {
		t.Fatal("downloadChromeExtensionCRXOnce returned nil error for HTTP 204")
	}
	var versionErr errExtensionNotAvailableForProdVersion
	if !errors.As(err, &versionErr) {
		t.Fatalf("error = %v, want errExtensionNotAvailableForProdVersion", err)
	}
	if !strings.Contains(err.Error(), "148.0.7778.215") {
		t.Fatalf("error = %q, want it to mention the prodversion", err.Error())
	}
}

// 200 但响应体为空同样说明商店没给包，不能当成下载成功。
func TestDownloadChromeExtensionCRXTreatsEmptyBodyAsVersionMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err := downloadChromeExtensionCRXOnce(context.Background(), server.Client(), server.URL+"/crx", "148.0.7778.215")
	if err == nil {
		t.Fatal("downloadChromeExtensionCRXOnce returned nil error for empty body")
	}
	var versionErr errExtensionNotAvailableForProdVersion
	if !errors.As(err, &versionErr) {
		t.Fatalf("error = %v, want errExtensionNotAvailableForProdVersion", err)
	}
}

// 正常拿到包时不能被误判成版本不匹配。
func TestDownloadChromeExtensionCRXReturnsPackageBody(t *testing.T) {
	payload := []byte("Cr24-package-bytes")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	data, err := downloadChromeExtensionCRXOnce(context.Background(), server.Client(), server.URL+"/crx", "148.0.7778.215")
	if err != nil {
		t.Fatalf("downloadChromeExtensionCRXOnce returned error: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("data = %q, want %q", data, payload)
	}
}
