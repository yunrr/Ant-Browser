package browser

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
)

// ExtensionRestoreIdentity resolves one side of a restore collision. The
// caller supplies its own local or staged root, never a path from the archive.
func ExtensionRestoreIdentity(extension Extension, managedRoot string, portable bool) (string, error) {
	extension.ManifestJSON, extension.installEvidence = decodeExtensionManifestRecord(extension.ManifestJSON)
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(extension.SourceURL)), "builtin://") {
		return registeredBuiltinRestoreIdentity(extension)
	}
	if err := checkExtensionRestoreRoot(managedRoot); err != nil {
		return "", err
	}
	var validatePath func(string, string) bool
	if !portable {
		validatePath = func(value, name string) bool {
			if !filepath.IsAbs(value) {
				value = filepath.Join(filepath.Dir(filepath.Dir(managedRoot)), value)
			}
			rel, err := filepath.Rel(filepath.Join(managedRoot, name), value)
			return err == nil && rel == "."
		}
	}
	return storedExtensionIdentityAt(extension, "", managedRoot, validatePath, false)
}

// VerifyRetainedExtensionCache checks the saved digest and independent package
// origin against all available installed manifests. Staged roots supply only
// manifest evidence, not another package or a separate claim about identity.
func VerifyRetainedExtensionCache(extension Extension, managedRoot string, stagedRoots ...string) (bool, error) {
	if !extensionIDPattern.MatchString(extension.ExtensionID) || !ValidExtensionPackageHash(strings.TrimSpace(extension.PackageHash)) {
		return false, nil
	}
	if err := checkExtensionRestoreRoot(managedRoot); err != nil {
		return false, err
	}
	extension.ManifestJSON, extension.installEvidence = decodeExtensionManifestRecord(extension.ManifestJSON)
	_, err := storedExtensionIdentityAt(extension, "", managedRoot, nil, true, stagedRoots...)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func checkExtensionRestoreRoot(root string) error {
	if root == "" {
		return nil
	}
	resolved, err := resolveManagedExtensionRoot(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if rel, err := filepath.Rel(root, resolved); err != nil || rel != "." {
		return fmt.Errorf("插件恢复存储目录不在受管路径")
	}
	return nil
}

func registeredBuiltinRestoreIdentity(extension Extension) (string, error) {
	for _, spec := range builtinExtensionSpecs {
		if extension.ExtensionID != spec.ID || extension.SourceURL != "builtin://"+spec.Dir {
			continue
		}
		registered, err := builtinExtensionFS.ReadFile(path.Join(builtinExtensionAssetRoot, spec.Dir, "manifest.json"))
		if err != nil {
			return "", err
		}
		var want, got map[string]any
		if json.Unmarshal(registered, &want) != nil || json.Unmarshal([]byte(extension.ManifestJSON), &got) != nil {
			break
		}
		if _, err := parseExtensionManifest([]byte(extension.ManifestJSON)); err != nil {
			return "", err
		}
		// Recognize only the explicitly registered asset; its version may differ.
		delete(want, "version")
		delete(got, "version")
		if reflect.DeepEqual(want, got) {
			return "builtin://" + spec.Dir, nil
		}
		break
	}
	return "", fmt.Errorf("无法证实已登记的内置插件来源")
}
