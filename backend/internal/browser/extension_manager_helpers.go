package browser

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
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
	var root map[string]json.RawMessage
	if err := json.Unmarshal(manifestData, &root); err != nil {
		return nil, fmt.Errorf("解析插件 manifest 失败: %w", err)
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
	if err := os.WriteFile(manifestPath, updated, 0o644); err != nil {
		return nil, fmt.Errorf("写入插件 manifest 失败: %w", err)
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

// extensionIdentityManifest 返回去掉版本字段后的 manifest 字节。
//
// 插件 ID 必须跨版本稳定：如果直接对整份 manifest 取哈希，升级时 version 变了
// ID 就跟着变，同一个插件会被当成"另一个插件"装进新目录 —— 旧版本仍然留在库里、
// 实例配置还指向旧 ID，浏览器继续加载旧代码。这里把版本相关字段剔除后再哈希。
//
// key 也要剔除：安装时会把 CRX 公钥补写进磁盘上的 manifest.key，而商店包里
// 通常没有这个字段。若把 key 计入身份，同一次安装前后算出的身份就不一致，
// 从本地 zip/目录重新安装同一插件会凭空多出一条记录。
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
