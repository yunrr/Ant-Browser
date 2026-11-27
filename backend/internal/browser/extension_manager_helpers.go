package browser

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func extractExtensionIDFromURL(rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return ""
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		candidate := strings.ToLower(strings.TrimSpace(parts[i]))
		if extensionIDPattern.MatchString(candidate) {
			return candidate
		}
	}
	return ""
}

// errExtensionNotAvailableForProdVersion 表示商店按当前 prodversion 拒绝下发安装包。
//
// 商店在插件要求的最低 Chrome 版本高于 prodversion 时返回 HTTP 204 空响应
// （不是错误码，所以必须显式识别，否则会被当成下载成功、读出 0 字节）。
type errExtensionNotAvailableForProdVersion struct {
	prodVersion string
}

func (e errExtensionNotAvailableForProdVersion) Error() string {
	return fmt.Sprintf("插件商店未按当前内核版本 %s 下发安装包（HTTP 204）；该插件要求更高的 Chrome 版本，或已从商店下架", e.prodVersion)
}

func downloadChromeExtensionCRX(ctx context.Context, extensionID string, prodVersion string, client *http.Client) ([]byte, error) {
	if client == nil {
		client = &http.Client{Timeout: extensionDownloadTimeout}
	}
	downloadURL := BuildChromeExtensionDownloadURLWithProdVersion(extensionID, prodVersion)
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		data, err := downloadChromeExtensionCRXOnce(ctx, client, downloadURL, prodVersion)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if !isRetryableExtensionDownloadError(err) {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt) * 250 * time.Millisecond):
		}
	}
	return nil, formatExtensionDownloadError(lastErr)
}

func downloadChromeExtensionCRXOnce(ctx context.Context, client *http.Client, downloadURL string, prodVersion string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Mozilla/5.0 AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	request.Header.Set("Accept", "*/*")
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("下载插件失败: %w", err)
	}
	defer response.Body.Close()
	// 204 是商店「按该版本不提供安装包」的正常应答，必须单独识别，
	// 不能落进 2xx 成功分支，否则后续只会报「插件包不是有效的 CRX/ZIP 文件」。
	if response.StatusCode == http.StatusNoContent {
		return nil, errExtensionNotAvailableForProdVersion{prodVersion: prodVersion}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("下载插件失败: HTTP %d", response.StatusCode)
	}
	limited := io.LimitReader(response.Body, extensionMaxPackageBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("读取插件包失败: %w", err)
	}
	if len(data) > extensionMaxPackageBytes {
		return nil, fmt.Errorf("插件包超过限制")
	}
	if len(data) == 0 {
		return nil, errExtensionNotAvailableForProdVersion{prodVersion: prodVersion}
	}
	return data, nil
}

func isRetryableExtensionDownloadError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "eof") ||
		strings.Contains(message, "connection reset") ||
		strings.Contains(message, "connection refused") ||
		strings.Contains(message, "timeout") ||
		strings.Contains(message, "temporarily unavailable")
}

func formatExtensionDownloadError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "eof") {
		return fmt.Errorf("下载插件失败: 连接在下载过程中提前关闭（EOF），已重试 3 次仍失败；请换一个下载代理节点或稍后重试")
	}
	if strings.Contains(message, "connectex") || strings.Contains(message, "dial tcp") || strings.Contains(message, "i/o timeout") {
		return fmt.Errorf("下载插件失败: 无法连接 Chrome 插件下载服务，请确认网络或下载代理可访问 clients2.google.com: %w", err)
	}
	return err
}

func normalizeExtensionArchiveData(data []byte) ([]byte, error) {
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return data, nil
	}
	zipOffset := bytes.Index(data, []byte("PK\x03\x04"))
	if zipOffset < 0 {
		return nil, fmt.Errorf("插件包不是有效的 CRX/ZIP 文件")
	}
	return data[zipOffset:], nil
}

func readExtensionManifestFromZip(data []byte) ([]byte, error) {
	return readExtensionArchiveManifest(bytes.NewReader(data), int64(len(data)))
}

func readExtensionArchiveManifest(data io.ReaderAt, size int64) ([]byte, error) {
	reader, err := zip.NewReader(data, size)
	if err != nil {
		return nil, fmt.Errorf("打开插件包失败: %w", err)
	}
	for _, file := range reader.File {
		if normalizeZipEntryPath(file.Name) == "manifest.json" {
			return readZipFile(file, 2<<20)
		}
	}
	return nil, fmt.Errorf("插件包缺少 manifest.json")
}

func parseExtensionManifest(data []byte) (extensionManifest, error) {
	var manifest extensionManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, fmt.Errorf("解析 manifest.json 失败: %w", err)
	}
	if strings.TrimSpace(manifest.Version) == "" {
		return manifest, fmt.Errorf("manifest.json 缺少 version")
	}
	return manifest, nil
}

func readExtensionLocaleMessagesFromZip(data []byte, manifest extensionManifest) map[string]string {
	locale := resolveExtensionLocale(manifest)
	if locale == "" {
		return nil
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if strings.EqualFold(normalizeZipEntryPath(file.Name), "_locales/"+locale+"/messages.json") {
			content, err := readZipFile(file, 1<<20)
			if err != nil {
				return nil
			}
			return parseExtensionLocaleMessages(content)
		}
	}
	return nil
}

func readExtensionLocaleMessagesFromDir(sourceDir string, manifest extensionManifest) map[string]string {
	locale := resolveExtensionLocale(manifest)
	if locale == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(sourceDir, "_locales", locale, "messages.json"))
	if err != nil {
		return nil
	}
	return parseExtensionLocaleMessages(data)
}

func parseExtensionLocaleMessages(data []byte) map[string]string {
	var raw map[string]struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	messages := make(map[string]string, len(raw))
	for key, value := range raw {
		if key = strings.TrimSpace(key); key != "" {
			messages[key] = strings.TrimSpace(value.Message)
		}
	}
	return messages
}

func resolveExtensionLocale(manifest extensionManifest) string {
	locale := strings.TrimSpace(manifest.DefaultLocale)
	locale = strings.Trim(locale, "/\\. ")
	if locale == "" || strings.Contains(locale, "/") || strings.Contains(locale, "\\") {
		return ""
	}
	return locale
}

func resolveExtensionDescription(manifest extensionManifest, messages map[string]string) string {
	return resolveExtensionMessage(strings.TrimSpace(manifest.Description), messages)
}

func resolveExtensionMessage(value string, messages map[string]string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "__MSG_") || !strings.HasSuffix(trimmed, "__") {
		return trimmed
	}
	key := strings.TrimSuffix(strings.TrimPrefix(trimmed, "__MSG_"), "__")
	if message := strings.TrimSpace(messages[key]); message != "" {
		return message
	}
	return trimmed
}

func readExtensionIconDataURLFromZip(data []byte, manifest extensionManifest) string {
	iconPath := resolveExtensionIconPath(manifest)
	if iconPath == "" {
		return ""
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return ""
	}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		if strings.EqualFold(normalizeZipEntryPath(file.Name), iconPath) {
			content, err := readZipFile(file, 1<<20)
			if err != nil {
				return ""
			}
			return extensionIconDataURL(iconPath, content)
		}
	}
	return ""
}

func readExtensionIconDataURLFromDir(sourceDir string, manifest extensionManifest) string {
	iconPath := resolveExtensionIconPath(manifest)
	if iconPath == "" {
		return ""
	}
	fullPath := filepath.Join(sourceDir, filepath.FromSlash(iconPath))
	content, err := os.ReadFile(fullPath)
	if err != nil || len(content) > 1<<20 {
		return ""
	}
	return extensionIconDataURL(iconPath, content)
}

func resolveExtensionIconPath(manifest extensionManifest) string {
	for _, candidate := range []map[string]any{manifest.Action, manifest.BrowserAction} {
		if path := mapStringValue(candidate, "default_icon"); path != "" {
			return normalizeExtensionAssetPath(path)
		}
	}
	bestSize := -1
	bestPath := ""
	for size, path := range manifest.Icons {
		if normalizedPath := normalizeExtensionAssetPath(path); normalizedPath != "" {
			parsedSize := parseExtensionIconSize(size)
			if parsedSize > bestSize {
				bestSize = parsedSize
				bestPath = normalizedPath
			}
		}
	}
	return bestPath
}

func mapStringValue(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	if value, ok := values[key].(string); ok {
		return value
	}
	if nested, ok := values[key].(map[string]any); ok {
		bestSize := -1
		bestPath := ""
		for size, rawPath := range nested {
			path, ok := rawPath.(string)
			if !ok {
				continue
			}
			parsedSize := parseExtensionIconSize(size)
			if parsedSize > bestSize {
				bestSize = parsedSize
				bestPath = path
			}
		}
		return bestPath
	}
	return ""
}

func normalizeExtensionAssetPath(value string) string {
	path := strings.TrimSpace(filepath.ToSlash(value))
	path = strings.TrimLeft(path, "/")
	if path == "" || strings.Contains(path, "..") || filepath.IsAbs(path) {
		return ""
	}
	return path
}

func parseExtensionIconSize(value string) int {
	var size int
	_, _ = fmt.Sscanf(strings.TrimSpace(value), "%d", &size)
	return size
}

func extensionIconDataURL(path string, data []byte) string {
	if len(data) == 0 || len(data) > 1<<20 {
		return ""
	}
	mimeType := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
	if mimeType == "" {
		mimeType = http.DetectContentType(data)
	}
	if !strings.HasPrefix(mimeType, "image/") {
		return ""
	}
	return "data:" + mimeType + ";base64," + base64.StdEncoding.EncodeToString(data)
}

func replaceExtensionDirFromZip(data []byte, installDir string) error {
	tmpDir := installDir + ".tmp"
	_ = os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("创建插件目录失败: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("打开插件包失败: %w", err)
	}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		relativePath := normalizeZipEntryPath(file.Name)
		if relativePath == "" {
			continue
		}
		targetPath := filepath.Join(tmpDir, filepath.FromSlash(relativePath))
		if !strings.HasPrefix(filepath.Clean(targetPath), filepath.Clean(tmpDir)+string(os.PathSeparator)) {
			return fmt.Errorf("插件包包含非法路径: %s", file.Name)
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return fmt.Errorf("创建插件文件目录失败: %w", err)
		}
		content, err := readZipFile(file, extensionMaxPackageBytes)
		if err != nil {
			return err
		}
		if err := os.WriteFile(targetPath, content, 0o644); err != nil {
			return fmt.Errorf("写入插件文件失败: %w", err)
		}
	}
	if err := os.RemoveAll(installDir); err != nil {
		return fmt.Errorf("清理旧插件失败: %w", err)
	}
	if err := os.Rename(tmpDir, installDir); err != nil {
		return fmt.Errorf("安装插件失败: %w", err)
	}
	success = true
	return nil
}

func copyExtensionDirectory(sourceDir string, installDir string) error {
	tmpDir := installDir + ".tmp"
	_ = os.RemoveAll(tmpDir)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fmt.Errorf("创建插件目录失败: %w", err)
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	sourceClean, err := filepath.Abs(sourceDir)
	if err != nil {
		return err
	}
	if err := filepath.WalkDir(sourceClean, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("插件目录包含符号链接: %s", path)
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > extensionMaxPackageBytes {
			return fmt.Errorf("插件文件过大: %s", path)
		}
		relativePath, err := filepath.Rel(sourceClean, path)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(tmpDir, relativePath)
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(targetPath, data, 0o644)
	}); err != nil {
		return fmt.Errorf("复制插件目录失败: %w", err)
	}
	if err := os.RemoveAll(installDir); err != nil {
		return fmt.Errorf("清理旧插件失败: %w", err)
	}
	if err := os.Rename(tmpDir, installDir); err != nil {
		return fmt.Errorf("安装插件失败: %w", err)
	}
	success = true
	return nil
}

func normalizeZipEntryPath(value string) string {
	path := strings.TrimSpace(filepath.ToSlash(value))
	path = strings.TrimLeft(path, "/")
	if path == "" || strings.Contains(path, "..") || filepath.IsAbs(path) {
		return ""
	}
	parts := strings.Split(path, "/")
	if len(parts) > 1 && parts[0] != "" && parts[1] == "manifest.json" {
		return strings.Join(parts[1:], "/")
	}
	return path
}

// extensionManifestKey 把 CRX 里的签名公钥转成 manifest 的 key 字段值。
//
// 未打包加载（--load-extension / Extensions.loadUnpacked）时，Chrome 优先用
// manifest.key 的哈希算扩展 ID；没有 key 就退回用目录绝对路径算，得到的 ID
// 与商店 ID 不同。ID 一变，依赖 allowed_origins 的原生消息宿主（1Password、
// Bitwarden 的桌面集成）就会拒绝连接，用户看到的是「插件装了但用不了」。
func extensionManifestKey(publicKey []byte) string {
	if len(publicKey) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(publicKey)
}

// ensureExtensionManifestKey 在解包目录的 manifest.json 里补写 key。
//
// 返回写入后的 manifest 字节；manifest 已带 key 或无需改动时返回 nil。
func ensureExtensionManifestKey(installDir string, publicKey []byte) ([]byte, error) {
	key := extensionManifestKey(publicKey)
	if key == "" {
		return nil, nil
	}
	manifestPath := filepath.Join(installDir, "manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("读取插件 manifest 失败: %w", err)
	}
	updated, err := manifestWithExtensionKey(manifestData, key)
	if err != nil || updated == nil {
		return updated, err
	}
	if err := os.WriteFile(manifestPath, updated, 0o644); err != nil {
		return nil, fmt.Errorf("写入插件 manifest 失败: %w", err)
	}
	return updated, nil
}

// manifestWithExtensionKey applies the existing local manifest augmentation without writing files.
func manifestWithExtensionKey(manifestData []byte, key string) ([]byte, error) {
	if key == "" {
		return nil, nil
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(manifestData, &root); err != nil {
		return nil, fmt.Errorf("解析插件 manifest 失败: %w", err)
	}
	if root == nil {
		return nil, fmt.Errorf("插件 manifest 不是 JSON 对象")
	}
	if existing, ok := root["key"]; ok {
		var existingKey string
		if json.Unmarshal(existing, &existingKey) == nil && strings.TrimSpace(existingKey) != "" {
			// 商店包里自带 key 的插件（例如 Proton Pass）已经是对的，不要覆盖。
			return nil, nil
		}
	}
	encodedKey, err := json.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("编码插件 manifest key 失败: %w", err)
	}
	root["key"] = encodedKey
	updated, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化插件 manifest 失败: %w", err)
	}
	return updated, nil
}

func readZipFile(file *zip.File, limit int64) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("读取插件文件失败: %w", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("读取插件文件失败: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("插件文件过大: %s", file.Name)
	}
	return data, nil
}

func extensionIDFromManifest(manifestData []byte) string {
	sum := sha256.Sum256(manifestData)
	return extensionIDFromHashBytes(sum[:16])
}

// extensionInstallIdentity combines external identity evidence, not management IDs.
// This validates identity consistency and encoding, not signature authenticity.
func extensionInstallIdentity(manifestData []byte, externalIDs ...string) (string, error) {
	var root map[string]json.RawMessage
	if len(bytes.TrimSpace(manifestData)) != 0 {
		if err := json.Unmarshal(manifestData, &root); err != nil || root == nil {
			return "", fmt.Errorf("无法识别插件清单身份")
		}
	}
	identityID := ""
	if raw, exists := root["key"]; exists {
		var key *string
		if err := json.Unmarshal(raw, &key); err != nil || key == nil {
			return "", fmt.Errorf("插件 manifest.key 格式无效")
		}
		if *key != "" {
			publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(*key))
			if err != nil || len(publicKey) == 0 {
				return "", fmt.Errorf("插件 manifest.key 格式无效")
			}
			identityID = extensionIDFromPublicKey(publicKey)
		}
	}
	for _, id := range externalIDs {
		if id == "" {
			continue
		}
		if !extensionIDPattern.MatchString(id) || (identityID != "" && identityID != id) {
			return "", fmt.Errorf("插件身份信息不一致")
		}
		identityID = id
	}
	return identityID, nil
}

// Only a recognized store origin and detail path establish a store identity.
func extensionIDFromStoreSource(source string) string {
	parsed, err := url.Parse(strings.TrimSpace(source))
	if err != nil || parsed.Scheme != "https" || parsed.User != nil {
		return ""
	}
	var prefix string
	switch strings.ToLower(parsed.Host) {
	case "chromewebstore.google.com":
		prefix = "/detail/"
	case "chrome.google.com":
		prefix = "/webstore/detail/"
	default:
		return ""
	}
	if !strings.HasPrefix(parsed.Path, prefix) {
		return ""
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(parsed.Path, prefix), "/"), "/")
	if len(parts) > 2 || (len(parts) == 2 && parts[0] == "") {
		return ""
	}
	id := parts[len(parts)-1]
	if !extensionIDPattern.MatchString(id) {
		return ""
	}
	return id
}

// targetID limits expensive checks when only a strong match could matter.
// An empty target also checks whether matching by manifest shape is safe.
func (m *Manager) storedExtensionIdentity(extension Extension, targetID string) (string, error) {
	return storedExtensionIdentityAt(extension, targetID, m.ResolveRelativePath(filepath.Join("data", extensionsRootDir)), m.isManagedExtensionPath, false)
}

// A nil path validator denotes portable metadata: serialized paths are never read.
func storedExtensionIdentityAt(extension Extension, targetID, managedRoot string, validatePath func(path, name string) bool, retainedCache bool, stagedRoots ...string) (string, error) {
	recorded := []byte(extension.ManifestJSON)
	manifestID, err := extensionInstallIdentity(recorded)
	if err != nil {
		return "", err
	}
	storeID := extensionIDFromStoreSource(extension.SourceURL)
	evidence := extension.installEvidence
	original, originID, err := storedInstallOrigin(recorded, storeID, evidence)
	if err != nil {
		return "", err
	}
	knownOrigin := original != nil
	if knownOrigin && targetID != "" && originID != targetID {
		return "", nil
	}
	packagePath := strings.TrimSpace(extension.PackagePath)
	packageHash := strings.TrimSpace(extension.PackageHash)
	hasPackageHistory := packagePath != "" || packageHash != "" || (evidence != nil && evidence.UnverifiedCache)
	if !hasPackageHistory && targetID != "" && targetID != originID && targetID != manifestID && targetID != storeID {
		return "", nil
	}
	var packageName, root string
	if hasPackageHistory {
		if !extensionIDPattern.MatchString(extension.ExtensionID) {
			return "", fmt.Errorf("历史插件包缺少有效来源校验信息")
		}
		packageName = filepath.Join("packages", extension.ExtensionID+".crx")
		if packagePath != "" && validatePath != nil && (!ValidExtensionPackageHash(packageHash) || !validatePath(packagePath, packageName)) {
			return "", fmt.Errorf("历史插件包缺少受管路径或有效来源校验信息")
		}
	}
	if managedRoot != "" && (extensionIDPattern.MatchString(extension.ExtensionID) || strings.TrimSpace(extension.InstallDir) != "") {
		root, err = resolveManagedExtensionRoot(managedRoot)
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	installed, err := readStoredInstalledManifest(root, extension, validatePath)
	if err != nil {
		return "", err
	}
	if knownOrigin && installed != nil && !bytes.Equal(installed, recorded) && !bytes.Equal(installed, original) {
		return "", fmt.Errorf("历史插件记录与已安装清单不一致")
	}

	var file *os.File
	if hasPackageHistory && root != "" {
		file, err = openManagedExtensionFile(root, packageName)
		if err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("无法打开历史插件包: %w", err)
		}
	}
	if file == nil {
		if retainedCache {
			return "", os.ErrNotExist
		}
		if knownOrigin {
			return originID, nil
		}
		return storedIdentityWithoutPackage(recorded, installed, storeID, hasPackageHistory)
	}
	defer file.Close()
	// A digest can outlive a cache path. If bytes are actually present, a
	// missing/quarantined reference must not turn them into an absent cache.
	if !ValidExtensionPackageHash(packageHash) || (packagePath == "" && validatePath != nil) || (evidence != nil && evidence.UnverifiedCache) {
		return "", fmt.Errorf("历史插件包来源未经校验")
	}
	originalPackage := knownOrigin && evidence.OriginalHash != "" && strings.EqualFold(packageHash, evidence.OriginalHash)
	generated := knownOrigin && evidence.GeneratedHash != "" && strings.EqualFold(packageHash, evidence.GeneratedHash)
	if retainedCache && knownOrigin && !originalPackage && !generated {
		return "", fmt.Errorf("缺少独立的插件包安装来源")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > extensionMaxPackageBytes {
		return "", fmt.Errorf("历史插件包无效")
	}
	header, err := readStoredCRXHeader(file, info.Size())
	if err != nil {
		return "", err
	}
	packageID := extensionIDFromCRX(header)
	if packageID == "" {
		return "", fmt.Errorf("无法识别历史 CRX 插件身份")
	}
	if targetID != "" && targetID != packageID && targetID != originID && targetID != manifestID && targetID != storeID {
		return "", nil
	}

	digest := sha256.New()
	if n, err := io.Copy(digest, io.NewSectionReader(file, 0, info.Size()+1)); err != nil || n != info.Size() || !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), packageHash) {
		return "", fmt.Errorf("历史插件包校验信息不一致")
	}
	offset := int64(len(header))
	archive := io.NewSectionReader(file, offset, info.Size()-offset)
	archived, err := readExtensionArchiveManifest(archive, archive.Size())
	if err != nil {
		return "", fmt.Errorf("无法读取历史插件原包清单: %w", err)
	}
	if _, err := parseExtensionManifest(archived); err != nil {
		return "", err
	}
	var stagedManifests [][]byte
	for _, stagedRoot := range stagedRoots {
		if err := checkExtensionRestoreRoot(stagedRoot); err != nil {
			return "", err
		}
		manifest, err := readStoredInstalledManifest(stagedRoot, extension, nil)
		if err != nil {
			return "", err
		}
		if manifest == nil {
			continue
		}
		if knownOrigin && !bytes.Equal(manifest, recorded) && !bytes.Equal(manifest, original) {
			return "", fmt.Errorf("历史插件记录与暂存安装清单不一致")
		}
		stagedManifests = append(stagedManifests, manifest)
	}
	if originalPackage {
		if packageID != originID || !bytes.Equal(archived, original) {
			return "", fmt.Errorf("历史插件原包与安装来源不一致")
		}
		return originID, nil
	}
	if bytes.Equal(archived, recorded) && (installed == nil || bytes.Equal(installed, recorded)) &&
		(generated || (!retainedCache && managedPackKeyMatches(root, extension.ExtensionID, header, packageID))) {
		// A generated package copies the installed manifest. Neither its
		// header ID nor a second copy of that manifest proves original identity.
		if knownOrigin {
			return originID, nil
		}
		identity, err := storedIdentityWithoutPackage(recorded, installed, storeID, false)
		if err == nil && identity == "" && installed == nil {
			return "", fmt.Errorf("无法证实历史插件清单的原始身份")
		}
		return identity, err
	}
	if knownOrigin {
		return "", fmt.Errorf("历史插件包与已知安装来源不一致")
	}
	if retainedCache && storeID == "" {
		// Pre-marker local originals need a key in the archive itself. A
		// package made with the local pack key cannot establish that origin.
		archivedID, err := extensionInstallIdentity(archived)
		if err != nil || archivedID != packageID || managedPackKeyMatches(root, extension.ExtensionID, header, packageID) {
			return "", fmt.Errorf("缺少独立的插件包安装来源")
		}
	}
	publicKey := crxPublicKey(header)
	identity, err := storedOriginalPackageIdentity(recorded, installed, archived, publicKey, storeID, packageID)
	if err != nil {
		return "", err
	}
	for _, manifest := range stagedManifests {
		if _, err := storedOriginalPackageIdentity(recorded, manifest, archived, publicKey, storeID, packageID); err != nil {
			return "", err
		}
	}
	return identity, nil
}

// ValidExtensionPackageHash reports whether a saved cache digest can be checked.
func ValidExtensionPackageHash(hash string) bool {
	digest, err := hex.DecodeString(hash)
	return err == nil && len(digest) == sha256.Size
}

func storedInstallOrigin(recorded []byte, storeID string, evidence *extensionInstallEvidence) ([]byte, string, error) {
	if evidence == nil || !evidence.FromInstaller {
		return nil, "", nil
	}
	original := recorded
	if evidence.OriginalManifest != "" {
		original = []byte(evidence.OriginalManifest)
		if !matchesStoredKeyAugmentation(original, recorded) {
			return nil, "", fmt.Errorf("历史插件清单与原始安装记录不一致")
		}
	}
	identity, err := extensionInstallIdentity(original, storeID, evidence.Identity)
	if err != nil || evidence.Identity != identity {
		return nil, "", fmt.Errorf("历史插件原始安装身份不一致")
	}
	return original, identity, nil
}

func storedOriginalPackageIdentity(recorded, installed, archived, publicKey []byte, storeID, packageID string) (string, error) {
	if !bytes.Equal(recorded, archived) || (installed != nil && !bytes.Equal(installed, archived)) {
		augmented := recorded
		if bytes.Equal(recorded, archived) {
			augmented = installed
		}
		if installed != nil && !bytes.Equal(installed, archived) && !bytes.Equal(installed, augmented) {
			return "", fmt.Errorf("历史插件已安装清单内容不一致")
		}
		return originalCRXManifestIdentity(archived, augmented, publicKey, storeID, packageID)
	}
	identity, err := extensionInstallIdentity(recorded, storeID)
	if err == nil && identity == packageID {
		return identity, nil
	}
	return "", fmt.Errorf("无法确定历史插件包的来源")
}

func readStoredInstalledManifest(root string, extension Extension, validatePath func(path, name string) bool) ([]byte, error) {
	installDir := strings.TrimSpace(extension.InstallDir)
	if installDir != "" && validatePath != nil && (!extensionIDPattern.MatchString(extension.ExtensionID) || !validatePath(installDir, extension.ExtensionID)) {
		return nil, fmt.Errorf("历史插件安装目录不在受管路径")
	}
	// A cleared directory field does not hide a manifest in the standard
	// managed location. The management ID only locates the file.
	if !extensionIDPattern.MatchString(extension.ExtensionID) {
		return nil, nil
	}
	if root == "" {
		return nil, nil
	}
	data, err := readManagedExtensionFile(root, filepath.Join(extension.ExtensionID, "manifest.json"), extensionMaxPackageBytes)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("无法读取历史插件已安装清单: %w", err)
	}
	if _, err := parseExtensionManifest(data); err != nil {
		return nil, err
	}
	if _, err := extensionInstallIdentity(data); err != nil {
		return nil, err
	}
	return data, nil
}

func storedIdentityWithoutPackage(recorded, installed []byte, storeID string, hasPackageHistory bool) (string, error) {
	identityID, err := extensionInstallIdentity(recorded, storeID)
	if err != nil {
		return "", err
	}
	if installed != nil && !bytes.Equal(installed, recorded) {
		// A disk-only key is not proof of the original identity. A store ID
		// can independently explain it, but only for the exact augmentation.
		installedID, err := extensionInstallIdentity(installed)
		if err != nil || storeID == "" || installedID != storeID || !matchesStoredKeyAugmentation(recorded, installed) {
			return "", fmt.Errorf("历史插件记录与已安装清单不一致")
		}
	}
	if storeID == "" && (matchesStoredKeyAugmentation(nil, recorded) || (hasPackageHistory && (identityID == "" || installed == nil))) {
		// Historical rows may have lost both cache fields. Two identical
		// copies of a possible augmentation are still a single weak source.
		return "", fmt.Errorf("无法证实历史插件清单的原始身份")
	}
	return identityID, nil
}

// A nil original asks whether data could have been written by the importer's
// augmentation at all. This excludes ambiguity; it does not identify a package.
func matchesStoredKeyAugmentation(original, data []byte) bool {
	var fields map[string]json.RawMessage
	var key string
	if err := json.Unmarshal(data, &fields); err != nil || json.Unmarshal(fields["key"], &key) != nil {
		return false
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil || len(publicKey) == 0 {
		return false
	}
	if original == nil {
		delete(fields, "key")
		original, err = json.Marshal(fields)
		if err != nil {
			return false
		}
	}
	augmented, err := manifestWithExtensionKey(original, extensionManifestKey(publicKey))
	return err == nil && augmented != nil && bytes.Equal(augmented, data)
}

func (m *Manager) isManagedExtensionPath(path, name string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	if !filepath.IsAbs(path) {
		path = m.ResolveRelativePath(path)
	}
	expected := m.ResolveRelativePath(filepath.Join("data", extensionsRootDir, name))
	relative, err := filepath.Rel(expected, path)
	return err == nil && relative == "."
}

// Resolve the configured storage root, but don't mistake a dangling link or
// invalid ancestor for a root that is genuinely absent.
func resolveManagedExtensionRoot(path string) (string, error) {
	if _, err := os.Lstat(path); err != nil {
		if parent := filepath.Dir(path); os.IsNotExist(err) && parent != path {
			if _, parentErr := resolveManagedExtensionRoot(parent); parentErr != nil {
				return "", parentErr
			}
		}
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("无法解析历史插件存储目录: %v", err)
	}
	if info, err := os.Stat(resolved); err != nil || !info.IsDir() {
		return "", fmt.Errorf("历史插件存储目录无效")
	}
	return resolved, nil
}

func openManagedExtensionFile(root, name string) (*os.File, error) {
	// Check each component without following links before treating ENOENT
	// as absence. An invalid component must not open a recovery path.
	parts := strings.Split(name, string(filepath.Separator))
	path := root
	for i, part := range parts {
		path = filepath.Join(path, part)
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if i < len(parts)-1 && !info.IsDir() || i == len(parts)-1 && !info.Mode().IsRegular() {
			return nil, fmt.Errorf("历史插件文件无效")
		}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("无法解析历史插件文件: %v", err)
	}
	if rel, err := filepath.Rel(path, resolved); err != nil || rel != "." {
		return nil, fmt.Errorf("历史插件文件不在受管路径")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("无法读取历史插件文件: %v", err)
	}
	return file, nil
}

func readManagedExtensionFile(root, name string, limit int64) ([]byte, error) {
	file, err := openManagedExtensionFile(root, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("历史插件文件无效")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("历史插件文件读取失败")
	}
	return data, nil
}

func managedPackKeyMatches(root, extensionID string, header []byte, packageID string) bool {
	data, err := readManagedExtensionFile(root, filepath.Join("packages", extensionID+".pem"), 64<<10)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return false
	}
	signer, ok := key.(crypto.Signer)
	if err != nil || !ok {
		return false
	}
	publicKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || extensionIDFromPublicKey(publicKey) != packageID {
		return false
	}
	for _, packageKey := range crxPublicKeys(header) {
		if bytes.Equal(publicKey, packageKey) {
			return true
		}
	}
	return false
}

// Only the exact local augmentation of a consistent original manifest is
// eligible. Original package/source conflicts are never reconciled this way.
func originalCRXManifestIdentity(original, installed, publicKey []byte, storeID, packageID string) (string, error) {
	identity, err := extensionInstallIdentity(original, storeID, packageID)
	if err != nil || identity == "" {
		return "", fmt.Errorf("历史插件原包身份不一致")
	}
	augmented, err := manifestWithExtensionKey(original, extensionManifestKey(publicKey))
	if err != nil || augmented == nil || !bytes.Equal(augmented, installed) {
		return "", fmt.Errorf("无法确认历史插件清单的本地补写来源")
	}
	return identity, nil
}

// Parse the header before reading the full digest or opening the ZIP body.
func readStoredCRXHeader(file io.Reader, size int64) ([]byte, error) {
	fixed := make([]byte, 12)
	if _, err := io.ReadFull(file, fixed); err != nil || !isCRXExtensionPackage(fixed) {
		return nil, fmt.Errorf("历史插件包缺少有效 CRX 头")
	}
	headerSize := uint64(binary.LittleEndian.Uint32(fixed[8:12]))
	switch binary.LittleEndian.Uint32(fixed[4:8]) {
	case 2:
		extra := make([]byte, 4)
		if _, err := io.ReadFull(file, extra); err != nil {
			return nil, err
		}
		fixed = append(fixed, extra...)
		headerSize += uint64(binary.LittleEndian.Uint32(extra))
	case 3:
	default:
		return nil, fmt.Errorf("历史插件包 CRX 版本不受支持")
	}
	if uint64(len(fixed))+headerSize >= uint64(size) {
		return nil, fmt.Errorf("历史插件包 CRX 头长度无效")
	}
	header := append(fixed, make([]byte, int(headerSize))...)
	if _, err := io.ReadFull(file, header[len(fixed):]); err != nil {
		return nil, err
	}
	return header, nil
}

// extensionIdentityManifest is only a legacy shape comparison and fallback
// for manifest records without external identity. It is not an identity proof.
func extensionIdentityManifest(manifestData []byte) []byte {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(manifestData, &root); err != nil {
		return manifestData
	}
	for _, key := range []string{"version", "version_name", "key"} {
		delete(root, key)
	}
	normalized, err := json.Marshal(root)
	if err != nil {
		return manifestData
	}
	return normalized
}

func extensionIDFromIdentityManifest(manifestData []byte) string {
	sum := sha256.Sum256(extensionIdentityManifest(manifestData))
	return extensionIDFromHashBytes(sum[:16])
}

func extensionIDFromHashBytes(raw []byte) string {
	hexValue := hex.EncodeToString(raw)
	var builder strings.Builder
	for _, char := range hexValue {
		if char >= '0' && char <= '9' {
			builder.WriteByte(byte('a' + char - '0'))
			continue
		}
		builder.WriteByte(byte('k' + char - 'a'))
	}
	return builder.String()
}

func resolveExtensionName(manifest extensionManifest, fallback string) string {
	for _, value := range []string{manifest.Name, manifest.ShortName, fallback} {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return "Chrome 插件"
}
