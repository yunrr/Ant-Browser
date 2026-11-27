package browser

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// 未打包加载时 Chrome 优先用 manifest.key 算扩展 ID；没有 key 就用目录路径算，
// ID 与商店不一致，依赖 allowed_origins 的原生消息宿主会拒绝连接。
func TestEnsureExtensionManifestKeyWritesPublicKey(t *testing.T) {
	installDir := t.TempDir()
	manifestPath := filepath.Join(installDir, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"manifest_version":3,"name":"1Password","version":"8.12.46.29"}`), 0o644); err != nil {
		t.Fatalf("WriteFile manifest returned error: %v", err)
	}
	publicKey := []byte("test-public-key")

	updated, err := ensureExtensionManifestKey(installDir, publicKey)
	if err != nil {
		t.Fatalf("ensureExtensionManifestKey returned error: %v", err)
	}
	if updated == nil {
		t.Fatal("ensureExtensionManifestKey returned nil manifest, want it to write key")
	}

	var root map[string]any
	if err := json.Unmarshal(updated, &root); err != nil {
		t.Fatalf("Unmarshal updated manifest returned error: %v", err)
	}
	wantKey := base64.StdEncoding.EncodeToString(publicKey)
	if got := root["key"]; got != wantKey {
		t.Fatalf("manifest key = %v, want %q", got, wantKey)
	}
	if got := root["version"]; got != "8.12.46.29" {
		t.Fatalf("manifest version = %v, want it preserved", got)
	}

	onDisk, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("ReadFile manifest returned error: %v", err)
	}
	if string(onDisk) != string(updated) {
		t.Fatal("manifest on disk differs from returned bytes")
	}
}

// 商店包里自带 key 的插件（例如 Proton Pass）已经是对的，不能覆盖。
func TestEnsureExtensionManifestKeyKeepsExistingKey(t *testing.T) {
	installDir := t.TempDir()
	manifestPath := filepath.Join(installDir, "manifest.json")
	original := `{"manifest_version":3,"name":"Proton Pass","version":"1.0.0","key":"existing-key"}`
	if err := os.WriteFile(manifestPath, []byte(original), 0o644); err != nil {
		t.Fatalf("WriteFile manifest returned error: %v", err)
	}

	updated, err := ensureExtensionManifestKey(installDir, []byte("another-public-key"))
	if err != nil {
		t.Fatalf("ensureExtensionManifestKey returned error: %v", err)
	}
	if updated != nil {
		t.Fatalf("ensureExtensionManifestKey rewrote manifest with existing key: %s", updated)
	}
	onDisk, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("ReadFile manifest returned error: %v", err)
	}
	if string(onDisk) != original {
		t.Fatalf("manifest changed to %s, want it untouched", onDisk)
	}
}

// 没有公钥（例如纯 zip 包）时不应该改动 manifest。
func TestEnsureExtensionManifestKeyWithoutPublicKeyIsNoop(t *testing.T) {
	installDir := t.TempDir()
	manifestPath := filepath.Join(installDir, "manifest.json")
	original := `{"manifest_version":3,"name":"Zip Extension","version":"1.0.0"}`
	if err := os.WriteFile(manifestPath, []byte(original), 0o644); err != nil {
		t.Fatalf("WriteFile manifest returned error: %v", err)
	}

	updated, err := ensureExtensionManifestKey(installDir, nil)
	if err != nil {
		t.Fatalf("ensureExtensionManifestKey returned error: %v", err)
	}
	if updated != nil {
		t.Fatalf("ensureExtensionManifestKey returned %s, want nil", updated)
	}
}

// 仅测试历史无身份记录的清单形状与回退哈希，不代表最终安装身份。
func TestExtensionIdentityManifestIgnoresKey(t *testing.T) {
	withoutKey := []byte(`{"manifest_version":3,"name":"1Password","version":"8.12.46.29"}`)
	withKey := []byte(`{"manifest_version":3,"name":"1Password","version":"8.12.46.29","key":"c29tZS1rZXk="}`)

	if got, want := extensionIDFromIdentityManifest(withKey), extensionIDFromIdentityManifest(withoutKey); got != want {
		t.Fatalf("identity ID with key = %q, want %q (same as without key)", got, want)
	}

	// 版本仍然要剔除，key 剔除不能把版本稳定性一起丢掉。
	newer := []byte(`{"manifest_version":3,"name":"1Password","version":"8.12.47.10","key":"c29tZS1rZXk="}`)
	if got, want := extensionIDFromIdentityManifest(newer), extensionIDFromIdentityManifest(withoutKey); got != want {
		t.Fatalf("identity ID for newer version = %q, want %q", got, want)
	}
}
