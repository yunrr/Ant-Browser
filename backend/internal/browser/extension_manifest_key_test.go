package browser

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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

// crx3TestRawID 取 CRX3 signed_header_data.crx_id 使用的 16 字节 ID。
func crx3TestRawID(publicKey []byte) []byte {
	sum := sha256.Sum256(publicKey)
	return sum[:16]
}

// crx3TestHeader 组装 CRX3 头：声明的 crx_id 加若干 proof 公钥，顺序即 proof 顺序。
func crx3TestHeader(declaredID []byte, proofKeys ...[]byte) []byte {
	var header []byte
	for _, proofKey := range proofKeys {
		header = appendCRX3LengthDelimitedField(header, 2, appendCRX3LengthDelimitedField(nil, 1, proofKey))
	}
	if len(declaredID) != 0 {
		header = appendCRX3LengthDelimitedField(header, 10000, appendCRX3LengthDelimitedField(nil, 1, declaredID))
	}
	return header
}

func crx3TestPackage(t *testing.T, header []byte, manifestData []byte) []byte {
	t.Helper()
	var archive bytes.Buffer
	zipWriter := zip.NewWriter(&archive)
	manifestWriter, err := zipWriter.Create("manifest.json")
	if err != nil {
		t.Fatalf("Create manifest returned error: %v", err)
	}
	if _, err := manifestWriter.Write(manifestData); err != nil {
		t.Fatalf("Write manifest returned error: %v", err)
	}
	if err := zipWriter.Close(); err != nil {
		t.Fatalf("Close archive returned error: %v", err)
	}
	packageData := make([]byte, 12+len(header))
	copy(packageData[:4], []byte("Cr24"))
	binary.LittleEndian.PutUint32(packageData[4:8], 3)
	binary.LittleEndian.PutUint32(packageData[8:12], uint32(len(header)))
	copy(packageData[12:], header)
	return append(packageData, archive.Bytes()...)
}

func readManifestKey(t *testing.T, manifestPath string) (string, bool) {
	t.Helper()
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("ReadFile manifest returned error: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(manifestData, &root); err != nil {
		t.Fatalf("Unmarshal manifest returned error: %v", err)
	}
	key, ok := root["key"].(string)
	return key, ok
}

// #0058：CRX3 头可能带多个 proof 公钥，只有派生 ID 等于声明 ID 的那个才代表
// 插件身份。按数组顺序取第一个会把错误的 key 写进 manifest，让未打包加载算出的
// 扩展 ID 与商店 ID 不一致。
func TestCRX3PublicKeyMatchesDeclaredExtensionID(t *testing.T) {
	signingKey := []byte("crx3-signing-public-key")
	otherKey := []byte("crx3-other-proof-public-key")
	declaredID := crx3TestRawID(signingKey)
	if got, want := extensionIDFromBytes(declaredID), extensionIDFromPublicKey(signingKey); got != want {
		t.Fatalf("declared extension ID = %q, want %q", got, want)
	}

	for _, tc := range []struct {
		name       string
		declaredID []byte
		proofKeys  [][]byte
		want       []byte
	}{
		{name: "later-proof-matches", declaredID: declaredID, proofKeys: [][]byte{otherKey, signingKey}, want: signingKey},
		{name: "first-proof-matches", declaredID: declaredID, proofKeys: [][]byte{signingKey, otherKey}, want: signingKey},
		{name: "no-proof-matches", declaredID: declaredID, proofKeys: [][]byte{otherKey, []byte("crx3-third-proof-public-key")}, want: nil},
		{name: "no-declared-id-keeps-first-proof", proofKeys: [][]byte{otherKey, signingKey}, want: otherKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := crx3TestPackage(t, crx3TestHeader(tc.declaredID, tc.proofKeys...), []byte(`{"manifest_version":3,"name":"CRX3","version":"1.0.0"}`))
			if got := crxPublicKey(data); !bytes.Equal(got, tc.want) {
				t.Fatalf("crxPublicKey = %q, want %q", got, tc.want)
			}
			if tc.want == nil {
				if keyed, err := ensureExtensionManifestKey(t.TempDir(), crxPublicKey(data)); err != nil || keyed != nil {
					t.Fatalf("ensureExtensionManifestKey without a matching key = %s, %v; want nil", keyed, err)
				}
			}
		})
	}
}

// 安装路径必须写入选中的 proof 公钥，而不是头部的第一个公钥。
func TestExtensionInstallWritesMatchingCRX3ProofKey(t *testing.T) {
	m := newIsolationManager(t)
	signingKey := []byte("crx3-installed-signing-key")
	otherKey := []byte("crx3-first-proof-key")
	declaredID := crx3TestRawID(signingKey)
	manifestData := []byte(`{"manifest_version":3,"name":"CRX3 fixture","version":"1.0.0"}`)
	data := crx3TestPackage(t, crx3TestHeader(declaredID, otherKey, signingKey), manifestData)

	installed, err := m.InstallExtensionPackageBytes("", "", data, nil)
	if err != nil {
		t.Fatalf("InstallExtensionPackageBytes returned error: %v", err)
	}
	wantID := extensionIDFromPublicKey(signingKey)
	if installed.ExtensionID != wantID {
		t.Fatalf("installed extension ID = %q, want declared %q", installed.ExtensionID, wantID)
	}
	wantKey := base64.StdEncoding.EncodeToString(signingKey)
	if key, ok := readManifestKey(t, filepath.Join(installed.InstallDir, "manifest.json")); !ok || key != wantKey {
		t.Fatalf("installed manifest key = %q (present=%t), want %q", key, ok, wantKey)
	}
}

// 没有任何 proof 公钥匹配声明 ID 时，宁可不写 key 也不能写错身份。
func TestExtensionInstallSkipsUnmatchedCRX3ProofKeys(t *testing.T) {
	m := newIsolationManager(t)
	signingKey := []byte("crx3-declared-signing-key")
	otherKey := []byte("crx3-unrelated-proof-key")
	declaredID := crx3TestRawID(signingKey)
	manifestData := []byte(`{"manifest_version":3,"name":"CRX3 unmatched","version":"1.0.0"}`)
	data := crx3TestPackage(t, crx3TestHeader(declaredID, otherKey), manifestData)

	installed, err := m.InstallExtensionPackageBytes("", "", data, nil)
	if err != nil {
		t.Fatalf("InstallExtensionPackageBytes returned error: %v", err)
	}
	if installed.ExtensionID != extensionIDFromPublicKey(signingKey) {
		t.Fatalf("installed extension ID = %q, want declared %q", installed.ExtensionID, extensionIDFromPublicKey(signingKey))
	}
	if key, ok := readManifestKey(t, filepath.Join(installed.InstallDir, "manifest.json")); ok {
		t.Fatalf("installed manifest key = %q, want no key", key)
	}
}

// CRX2 行为保持不变：公钥直接来自头部，仍然写入 manifest.key。
func TestExtensionInstallWritesCRX2ManifestKey(t *testing.T) {
	m := newIsolationManager(t)
	publicKey := []byte("crx2-installed-public-key")
	extensionID := extensionIDFromPublicKey(publicKey)
	packagePath := filepath.Join(t.TempDir(), "crx2.crx")
	writeTestCRXPackage(t, packagePath, extensionID, "CRX2 fixture", "1.0.0", publicKey)

	installed, err := m.InstallExtensionPackageFile(packagePath, nil)
	if err != nil {
		t.Fatalf("InstallExtensionPackageFile returned error: %v", err)
	}
	if installed.ExtensionID != extensionID {
		t.Fatalf("installed extension ID = %q, want %q", installed.ExtensionID, extensionID)
	}
	wantKey := base64.StdEncoding.EncodeToString(publicKey)
	if key, ok := readManifestKey(t, filepath.Join(installed.InstallDir, "manifest.json")); !ok || key != wantKey {
		t.Fatalf("installed manifest key = %q (present=%t), want %q", key, ok, wantKey)
	}
}
