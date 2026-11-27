package backend

import (
	"ant-chrome/backend/internal/backup"
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
	"ant-chrome/backend/internal/database"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	backupTestExtensionID  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	backupTestExtensionIDB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	backupTestProfileID    = "profile-a"
	backupTestPackageData  = "Cr24-test-package"
	backupTestTimestamp    = "20260809-000000"
)

func TestBackupRepairExtensionPathsAfterImportRelocatesManagedArtifacts(t *testing.T) {
	app := newBackupExtensionRepairTestApp(t)
	oldRoot := t.TempDir()
	oldInstallDir := filepath.Join(oldRoot, "data", "extensions", backupTestExtensionID)
	oldPackagePath := filepath.Join(oldRoot, "data", "extensions", "packages", backupTestExtensionID+".crx")
	oldBackupPath := filepath.Join(oldRoot, "data", "extension-backups", backupTestProfileID, backupTestExtensionID, backupTestTimestamp)
	packageData := []byte(backupTestPackageData)
	packageHash := sha256Hex(packageData)

	insertBackupTestExtension(t, app, backupTestExtensionID, oldInstallDir, oldPackagePath, "old-hash")
	insertBackupTestRuntime(t, app, backupTestExtensionID, oldBackupPath, "old-runtime-hash")
	payloadRoot := writeBackupExtensionPayload(t, t.TempDir(), backupTestExtensionID, packageData, true, oldBackupPath)

	stats := &backupMergeStats{}
	app.backupImportFileTrees(payloadRoot, nil, backup.Manifest{}, stats, nil)
	if _, err := app.backupRepairExtensionPathsAfterImport(); err != nil {
		t.Fatalf("backupRepairExtensionPathsAfterImport returned error: %v", err)
	}

	newInstallDir := filepath.Join(app.appRoot, "data", "extensions", backupTestExtensionID)
	newPackagePath := filepath.Join(app.appRoot, "data", "extensions", "packages", backupTestExtensionID+".crx")
	newBackupPath := filepath.Join(app.appRoot, "data", "extension-backups", backupTestProfileID, backupTestExtensionID, backupTestTimestamp)
	gotInstallDir, gotPackagePath, gotPackageHash := readBackupTestExtension(t, app, backupTestExtensionID)
	if !backupSamePath(gotInstallDir, newInstallDir) {
		t.Fatalf("install_dir = %q, want %q", gotInstallDir, newInstallDir)
	}
	if !backupSamePath(gotPackagePath, newPackagePath) {
		t.Fatalf("package_path = %q, want %q", gotPackagePath, newPackagePath)
	}
	if gotPackageHash != packageHash {
		t.Fatalf("package_hash = %q, want %q", gotPackageHash, packageHash)
	}

	var gotBackupPath string
	if err := app.db.GetConn().QueryRow(`
		SELECT backup_path
		FROM browser_profile_extension_runtime
		WHERE profile_id = ? AND extension_id = ?`, backupTestProfileID, backupTestExtensionID).Scan(&gotBackupPath); err != nil {
		t.Fatalf("read runtime backup_path returned error: %v", err)
	}
	if !backupSamePath(gotBackupPath, newBackupPath) {
		t.Fatalf("runtime backup_path = %q, want %q", gotBackupPath, newBackupPath)
	}
	if !backupExtensionManifestExists(newInstallDir) {
		t.Fatalf("relocated plugin manifest does not exist at %q", newInstallDir)
	}
	if !backupExtensionRegularFileExists(newPackagePath) {
		t.Fatalf("relocated plugin package does not exist at %q", newPackagePath)
	}
}

func TestBackupRepairExtensionPathsClearsMissingManagedPackage(t *testing.T) {
	app := newBackupExtensionRepairTestApp(t)
	oldRoot := t.TempDir()
	oldInstallDir := filepath.Join(oldRoot, "data", "extensions", backupTestExtensionID)
	oldPackagePath := filepath.Join(oldRoot, "data", "extensions", "packages", backupTestExtensionID+".crx")
	payloadRoot := filepath.Join(t.TempDir(), "payload")

	insertBackupTestExtension(t, app, backupTestExtensionID, oldInstallDir, oldPackagePath, "old-hash")
	writeBackupExtensionPayload(t, payloadRoot, backupTestExtensionID, nil, false, "")

	stats := &backupMergeStats{}
	app.backupImportFileTrees(payloadRoot, nil, backup.Manifest{}, stats, nil)
	if _, err := app.backupRepairExtensionPathsAfterImport(); err != nil {
		t.Fatalf("backupRepairExtensionPathsAfterImport returned error: %v", err)
	}

	gotInstallDir, gotPackagePath, gotPackageHash := readBackupTestExtension(t, app, backupTestExtensionID)
	wantInstallDir := filepath.Join(app.appRoot, "data", "extensions", backupTestExtensionID)
	if !backupSamePath(gotInstallDir, wantInstallDir) {
		t.Fatalf("install_dir = %q, want %q", gotInstallDir, wantInstallDir)
	}
	if gotPackagePath != "" || gotPackageHash != "" {
		t.Fatalf("missing package metadata = (%q, %q), want empty values", gotPackagePath, gotPackageHash)
	}
}

func TestBackupRepairExtensionPathsClearsMissingManagedDirectory(t *testing.T) {
	app := newBackupExtensionRepairTestApp(t)
	oldRoot := t.TempDir()
	oldInstallDir := filepath.Join(oldRoot, "data", "extensions", backupTestExtensionID)
	payloadRoot := filepath.Join(t.TempDir(), "payload")
	if err := os.MkdirAll(filepath.Join(payloadRoot, "app", "data"), 0o755); err != nil {
		t.Fatalf("MkdirAll payload data returned error: %v", err)
	}

	insertBackupTestExtension(t, app, backupTestExtensionID, oldInstallDir, "", "")
	stats := &backupMergeStats{}
	app.backupImportFileTrees(payloadRoot, nil, backup.Manifest{}, stats, nil)
	if _, err := app.backupRepairExtensionPathsAfterImport(); err != nil {
		t.Fatalf("backupRepairExtensionPathsAfterImport returned error: %v", err)
	}

	gotInstallDir, _, _ := readBackupTestExtension(t, app, backupTestExtensionID)
	if gotInstallDir != "" {
		t.Fatalf("missing managed install_dir = %q, want empty value", gotInstallDir)
	}
}

func TestBackupRepairExtensionPathsRollsBackAllUpdatesOnFailure(t *testing.T) {
	app := newBackupExtensionRepairTestApp(t)
	oldRoot := t.TempDir()
	payloadRoot := t.TempDir()
	oldInstallDirA := filepath.Join(oldRoot, "data", "extensions", backupTestExtensionID)
	oldInstallDirB := filepath.Join(oldRoot, "data", "extensions", backupTestExtensionIDB)
	insertBackupTestExtension(t, app, backupTestExtensionID, oldInstallDirA, "", "")
	insertBackupTestExtension(t, app, backupTestExtensionIDB, oldInstallDirB, "", "")
	writeBackupExtensionPayload(t, payloadRoot, backupTestExtensionID, nil, false, "")
	writeBackupExtensionPayload(t, payloadRoot, backupTestExtensionIDB, nil, false, "")

	triggerSQL := fmt.Sprintf(`
		CREATE TRIGGER backup_extension_path_repair_failure
		BEFORE UPDATE OF install_dir ON browser_extensions
		WHEN OLD.extension_id = '%s'
		BEGIN
			SELECT RAISE(ABORT, 'forced extension path repair failure');
		END`, backupTestExtensionIDB)
	if _, err := app.db.GetConn().Exec(triggerSQL); err != nil {
		t.Fatalf("create rollback trigger returned error: %v", err)
	}

	stats := &backupMergeStats{}
	app.backupImportFileTrees(payloadRoot, nil, backup.Manifest{}, stats, nil)
	if _, err := app.backupRepairExtensionPathsAfterImport(); err == nil {
		t.Fatal("backupRepairExtensionPathsAfterImport returned nil, want forced failure")
	}

	gotInstallDirA, _, _ := readBackupTestExtension(t, app, backupTestExtensionID)
	gotInstallDirB, _, _ := readBackupTestExtension(t, app, backupTestExtensionIDB)
	if !backupSamePath(gotInstallDirA, oldInstallDirA) || !backupSamePath(gotInstallDirB, oldInstallDirB) {
		t.Fatalf("transaction did not roll back: install dirs = (%q, %q)", gotInstallDirA, gotInstallDirB)
	}
}

func TestBackupRepairExtensionPathsInvalidIDDoesNotBlockOthers(t *testing.T) {
	app := newBackupExtensionRepairTestApp(t)
	oldRoot := t.TempDir()
	oldInstallDir := filepath.Join(oldRoot, "data", "extensions", backupTestExtensionID)
	invalidID := "invalid-extension-id"
	invalidInstallDir := filepath.Join(oldRoot, "data", "extensions", invalidID)
	payloadRoot := t.TempDir()

	insertBackupTestExtension(t, app, backupTestExtensionID, oldInstallDir, "", "")
	insertBackupTestExtension(t, app, invalidID, invalidInstallDir, "", "")
	writeBackupExtensionPayload(t, payloadRoot, backupTestExtensionID, nil, false, "")

	stats := &backupMergeStats{}
	app.backupImportFileTrees(payloadRoot, nil, backup.Manifest{}, stats, nil)
	issues, err := app.backupRepairExtensionPathsAfterImport()
	if err != nil {
		t.Fatalf("backupRepairExtensionPathsAfterImport returned hard error: %v", err)
	}
	if len(issues) != 1 || !strings.Contains(issues[0].Error(), "插件 ID 无效") {
		t.Fatalf("issues = %v, want single invalid-ID issue", issues)
	}

	gotInstallDir, _, _ := readBackupTestExtension(t, app, backupTestExtensionID)
	wantInstallDir := filepath.Join(app.appRoot, "data", "extensions", backupTestExtensionID)
	if !backupSamePath(gotInstallDir, wantInstallDir) {
		t.Fatalf("valid extension install_dir = %q, want %q", gotInstallDir, wantInstallDir)
	}
	gotInvalidInstallDir, _, _ := readBackupTestExtension(t, app, invalidID)
	if !backupSamePath(gotInvalidInstallDir, invalidInstallDir) {
		t.Fatalf("invalid-ID extension install_dir = %q, want untouched %q", gotInvalidInstallDir, invalidInstallDir)
	}
}

func TestBackupRepairExtensionPathsReportsCorruptManifest(t *testing.T) {
	app := newBackupExtensionRepairTestApp(t)
	oldRoot := t.TempDir()
	oldInstallDir := filepath.Join(oldRoot, "data", "extensions", backupTestExtensionID)
	payloadRoot := t.TempDir()

	insertBackupTestExtension(t, app, backupTestExtensionID, oldInstallDir, "", "")
	writeBackupExtensionPayload(t, payloadRoot, backupTestExtensionID, nil, false, "")
	manifestPath := filepath.Join(payloadRoot, "app", "data", "extensions", backupTestExtensionID, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"name": "broken`), 0o644); err != nil {
		t.Fatalf("WriteFile corrupt manifest returned error: %v", err)
	}

	stats := &backupMergeStats{}
	app.backupImportFileTrees(payloadRoot, nil, backup.Manifest{}, stats, nil)
	issues, err := app.backupRepairExtensionPathsAfterImport()
	if err != nil {
		t.Fatalf("backupRepairExtensionPathsAfterImport returned hard error: %v", err)
	}
	if len(issues) != 1 || !strings.Contains(issues[0].Error(), "manifest.json 内容损坏") {
		t.Fatalf("issues = %v, want manifest corruption issue", issues)
	}

	gotInstallDir, _, _ := readBackupTestExtension(t, app, backupTestExtensionID)
	wantInstallDir := filepath.Join(app.appRoot, "data", "extensions", backupTestExtensionID)
	if !backupSamePath(gotInstallDir, wantInstallDir) {
		t.Fatalf("install_dir = %q, want %q", gotInstallDir, wantInstallDir)
	}
}

func TestBackupRepairExtensionPathsReportsCorruptCRX(t *testing.T) {
	app := newBackupExtensionRepairTestApp(t)
	oldRoot := t.TempDir()
	oldInstallDir := filepath.Join(oldRoot, "data", "extensions", backupTestExtensionID)
	oldPackagePath := filepath.Join(oldRoot, "data", "extensions", "packages", backupTestExtensionID+".crx")
	payloadRoot := t.TempDir()

	insertBackupTestExtension(t, app, backupTestExtensionID, oldInstallDir, oldPackagePath, "old-hash")
	writeBackupExtensionPayload(t, payloadRoot, backupTestExtensionID, []byte("not-a-crx"), true, "")

	stats := &backupMergeStats{}
	app.backupImportFileTrees(payloadRoot, nil, backup.Manifest{}, stats, nil)
	issues, err := app.backupRepairExtensionPathsAfterImport()
	if err != nil {
		t.Fatalf("backupRepairExtensionPathsAfterImport returned hard error: %v", err)
	}
	if len(issues) != 1 || !strings.Contains(issues[0].Error(), "不是合法 CRX") {
		t.Fatalf("issues = %v, want CRX corruption issue", issues)
	}

	gotInstallDir, gotPackagePath, gotPackageHash := readBackupTestExtension(t, app, backupTestExtensionID)
	wantInstallDir := filepath.Join(app.appRoot, "data", "extensions", backupTestExtensionID)
	if !backupSamePath(gotInstallDir, wantInstallDir) {
		t.Fatalf("install_dir = %q, want %q", gotInstallDir, wantInstallDir)
	}
	if gotPackagePath != "" || gotPackageHash != "" {
		t.Fatalf("corrupt package metadata = (%q, %q), want empty values", gotPackagePath, gotPackageHash)
	}
}

func TestBackupRepairExtensionPathsPreservesInstallIdentity(t *testing.T) {
	for _, tc := range []struct {
		name            string
		fresh           string
		hasDigest       bool
		legacyHash      bool
		cache           string
		missingManifest bool
		wantUpgrade     bool
	}{
		{name: "historical-copies-already-cleared"},
		{name: "historical-copies-cache-missing", hasDigest: true},
		{name: "historical-copies-digest-mismatch", hasDigest: true, cache: "mismatch"},
		{name: "historical-copies-digest-matches", hasDigest: true, cache: "original", wantUpgrade: true},
		{name: "historical-rebuilt-digest-is-not-evidence", hasDigest: true, legacyHash: true, cache: "original"},
		{name: "fresh-ordinary-keyed-directory", fresh: "directory", wantUpgrade: true},
		{name: "fresh-ordinary-keyed-zip", fresh: "zip", wantUpgrade: true},
		{name: "fresh-crx-cache-missing", fresh: "crx", wantUpgrade: true},
		{name: "fresh-crx-cache-and-manifest-missing", fresh: "crx", missingManifest: true, wantUpgrade: true},
		{name: "fresh-crx-only-manifest-missing", fresh: "crx", cache: "original", missingManifest: true, wantUpgrade: true},
		{name: "fresh-crx-contradictory-cache", fresh: "crx", cache: "mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := newBackupExtensionRepairTestApp(t)
			sourceMgr := newBackupIdentityManager(source)
			const name = "Backup identity fixture"
			publicKey := []byte("local fixture public key")
			key := base64.StdEncoding.EncodeToString(publicKey)
			original := backupIdentityManifest(t, name, "1.0", key)
			if tc.fresh == "crx" {
				original = backupIdentityManifest(t, name, "1.0", "")
			}
			var packageData []byte
			if tc.hasDigest || tc.fresh == "crx" {
				packageData = backupIdentityCRX(t, publicKey, original, "original")
			}
			var row browser.Extension
			if tc.fresh != "" {
				legacy, err := sourceMgr.InstallExtensionDirectory(backupIdentityDirectory(t, backupIdentityManifest(t, name, "1.0", "")), nil)
				if err != nil {
					t.Fatal(err)
				}
				switch tc.fresh {
				case "directory":
					row, err = sourceMgr.InstallExtensionDirectory(backupIdentityDirectory(t, original), nil)
				case "zip", "crx":
					input := packageData
					if tc.fresh == "zip" {
						input = backupIdentityZIP(t, original, "ordinary")
					}
					path := filepath.Join(t.TempDir(), "extension."+tc.fresh)
					if err := os.WriteFile(path, input, 0o644); err != nil {
						t.Fatal(err)
					}
					row, err = sourceMgr.InstallExtensionPackageFile(path, nil)
				}
				if err != nil || row.ExtensionID != legacy.ExtensionID {
					t.Fatalf("prepare a genuine original with legacy management ID: %v", err)
				}
			} else {
				row = browser.Extension{
					ExtensionID: backupTestExtensionID, Name: name, Version: "1.0", ManifestJSON: string(original),
					InstallDir: filepath.Join(source.appRoot, "data", "extensions", backupTestExtensionID),
				}
				if tc.hasDigest {
					row.PackagePath = filepath.Join(source.appRoot, "data", "extensions", "packages", row.ExtensionID+".crx")
					row.PackageHash = sha256Hex(packageData)
					if tc.legacyHash {
						row.PackageHash = "legacy-hash"
					}
				}
				if err := sourceMgr.ExtensionDAO.Upsert(row); err != nil {
					t.Fatal(err)
				}
			}
			if err := sourceMgr.ExtensionDAO.SetEnabled(row.ExtensionID, false); err != nil {
				t.Fatal(err)
			}
			if err := sourceMgr.ExtensionDAO.SetDefaultInstall(row.ExtensionID, true); err != nil {
				t.Fatal(err)
			}
			profile := &browser.Profile{ProfileId: backupTestProfileID, ProfileName: "Backup identity fixture", UserDataDir: backupTestProfileID}
			if err := browser.NewSQLiteProfileDAO(source.db.GetConn()).Upsert(profile); err != nil {
				t.Fatal(err)
			}
			if _, err := sourceMgr.ExtensionDAO.SetProfileSettings(backupTestProfileID, []string{row.ExtensionID}, true); err != nil {
				t.Fatal(err)
			}

			target := newBackupExtensionRepairTestApp(t)
			targetMgr := newBackupIdentityManager(target)
			if tc.cache == "mismatch" {
				// Still the same public identity and original manifest, only
				// the ordinary archive contents differ from the saved digest.
				packageData = backupIdentityCRX(t, publicKey, original, "different archive contents")
			}
			payloadRoot := writeBackupExtensionPayload(t, t.TempDir(), row.ExtensionID, packageData, tc.cache != "", "")
			payloadManifest := filepath.Join(payloadRoot, "app", "data", "extensions", row.ExtensionID, "manifest.json")
			var err error
			if tc.missingManifest {
				err = os.Remove(payloadManifest)
			} else {
				err = os.WriteFile(payloadManifest, []byte(row.ManifestJSON), 0o644)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := target.backupMergeDatabaseFromSource(filepath.Join(source.appRoot, "data", "app.db"), nil, &backupMergeStats{}); err != nil {
				t.Fatal(err)
			}
			target.backupImportFileTrees(payloadRoot, nil, backup.Manifest{}, &backupMergeStats{}, nil)
			issues, err := target.backupRepairExtensionPathsAfterImport()
			if err != nil {
				t.Fatal(err)
			}
			if tc.cache == "mismatch" && (len(issues) != 1 || !strings.Contains(issues[0].Error(), "校验信息不一致")) {
				t.Error("restore did not report the cache digest mismatch")
			}
			restored, err := targetMgr.ExtensionDAO.Get(row.ExtensionID)
			if err != nil {
				t.Fatal(err)
			}
			wantDigest := row.PackageHash
			if tc.legacyHash {
				wantDigest = sha256Hex(packageData)
			}
			if restored.PackageHash != wantDigest || restored.ManifestJSON != row.ManifestJSON {
				t.Error("restore discarded the saved digest or changed the exposed manifest")
			}
			if tc.cache != "original" && restored.PackagePath != "" {
				t.Error("restore retained an unusable cache path")
			}
			upgrade, err := targetMgr.InstallExtensionDirectory(backupIdentityDirectory(t, backupIdentityManifest(t, name, "2.0", key)), nil)
			if err != nil {
				t.Fatal(err)
			}
			if (upgrade.ExtensionID == row.ExtensionID) != tc.wantUpgrade {
				t.Error("install selected the wrong management ID for the restored evidence")
			}
			stored, err := targetMgr.ExtensionDAO.Get(row.ExtensionID)
			if err != nil {
				t.Fatal(err)
			}
			wantVersion := "1.0"
			if tc.wantUpgrade {
				wantVersion = "2.0"
			}
			portableDir := filepath.Join(target.appRoot, "data", "extensions", row.ExtensionID)
			if stored.Version != wantVersion || !backupSamePath(stored.InstallDir, portableDir) || stored.Enabled || !stored.DefaultInstall {
				t.Error("install changed the wrong restored record, path, or settings")
			}
			settings, err := targetMgr.ExtensionDAO.GetProfileSettings(backupTestProfileID)
			if err != nil || !settings.Configured || len(settings.ExtensionIDs) != 1 || settings.ExtensionIDs[0] != row.ExtensionID {
				t.Errorf("install did not preserve the restored profile binding: %v", err)
			}
		})
	}
}

func newBackupIdentityManager(app *App) *browser.Manager {
	m := browser.NewManager(config.DefaultConfig(), app.appRoot)
	m.ExtensionDAO = browser.NewSQLiteExtensionDAO(app.db.GetConn())
	return m
}

func backupIdentityManifest(t *testing.T, name, version, key string) []byte {
	t.Helper()
	fields := map[string]string{"name": name, "version": version}
	if key != "" {
		fields["key"] = key
	}
	data, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func backupIdentityCRX(t *testing.T, key, manifest []byte, contents string) []byte {
	t.Helper()
	// The header key is either absent from the manifest or matches it;
	// this inert fixture is used only to compare restored cache digests.
	header := make([]byte, 16, 16+len(key))
	copy(header, "Cr24")
	binary.LittleEndian.PutUint32(header[4:], 2)
	binary.LittleEndian.PutUint32(header[8:], uint32(len(key)))
	return append(append(header, key...), backupIdentityZIP(t, manifest, contents)...)
}

func backupIdentityZIP(t *testing.T, manifest []byte, contents string) []byte {
	t.Helper()
	var buf bytes.Buffer
	archive := zip.NewWriter(&buf)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"manifest.json", manifest}, {"fixture.txt", []byte(contents)}} {
		w, err := archive.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func backupIdentityDirectory(t *testing.T, manifest []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newBackupExtensionRepairTestApp(t *testing.T) *App {
	t.Helper()
	appRoot := t.TempDir()
	dataRoot := filepath.Join(appRoot, "data")
	if err := os.MkdirAll(dataRoot, 0o755); err != nil {
		t.Fatalf("MkdirAll data root returned error: %v", err)
	}
	db, err := database.NewDB(filepath.Join(dataRoot, "app.db"))
	if err != nil {
		t.Fatalf("NewDB returned error: %v", err)
	}
	if err := db.Migrate(); err != nil {
		_ = db.Close()
		t.Fatalf("Migrate returned error: %v", err)
	}
	app := NewApp(appRoot)
	app.db = db
	t.Cleanup(func() { _ = db.Close() })
	return app
}

func insertBackupTestExtension(t *testing.T, app *App, extensionID string, installDir string, packagePath string, packageHash string) {
	t.Helper()
	_, err := app.db.GetConn().Exec(`
		INSERT INTO browser_extensions (
			extension_id, name, version, manifest_json, source_url, install_dir,
			install_mode, package_path, package_hash, enabled, default_install,
			installed_at, updated_at
		) VALUES (?, 'test', '1.0.0', '{}', '', ?, 'persistent', ?, ?, 1, 0, ?, ?)`,
		extensionID, installDir, packagePath, packageHash, backupTestTimestamp, backupTestTimestamp)
	if err != nil {
		t.Fatalf("insert extension returned error: %v", err)
	}
}

func insertBackupTestRuntime(t *testing.T, app *App, extensionID string, backupPath string, packageHash string) {
	t.Helper()
	_, err := app.db.GetConn().Exec(`
		INSERT INTO browser_profile_extension_runtime (
			profile_id, extension_id, runtime_extension_id, install_mode,
			installed_version, package_hash, status, backup_path,
			last_verified_at, last_error, created_at, updated_at
		) VALUES (?, ?, ?, 'persistent', '1.0.0', ?, 'installed', ?, '', '', ?, ?)`,
		backupTestProfileID, extensionID, extensionID, packageHash, backupPath, backupTestTimestamp, backupTestTimestamp)
	if err != nil {
		t.Fatalf("insert runtime returned error: %v", err)
	}
}

func writeBackupExtensionPayload(t *testing.T, payloadRoot string, extensionID string, packageData []byte, includePackage bool, backupPath string) string {
	t.Helper()
	extensionDir := filepath.Join(payloadRoot, "app", "data", "extensions", extensionID)
	if err := os.MkdirAll(extensionDir, 0o755); err != nil {
		t.Fatalf("MkdirAll extension payload returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(extensionDir, "manifest.json"), []byte(`{"name":"Test","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatalf("WriteFile manifest returned error: %v", err)
	}
	if includePackage {
		packageDir := filepath.Join(payloadRoot, "app", "data", "extensions", "packages")
		if err := os.MkdirAll(packageDir, 0o755); err != nil {
			t.Fatalf("MkdirAll package payload returned error: %v", err)
		}
		if err := os.WriteFile(filepath.Join(packageDir, extensionID+".crx"), packageData, 0o644); err != nil {
			t.Fatalf("WriteFile package returned error: %v", err)
		}
	}
	if backupPath != "" {
		backupSuffix := filepath.Base(backupPath)
		backupDir := filepath.Join(payloadRoot, "app", "data", "extension-backups", backupTestProfileID, extensionID, backupSuffix)
		if err := os.MkdirAll(backupDir, 0o755); err != nil {
			t.Fatalf("MkdirAll backup payload returned error: %v", err)
		}
		if err := os.WriteFile(filepath.Join(backupDir, "state.bin"), []byte("state"), 0o644); err != nil {
			t.Fatalf("WriteFile backup state returned error: %v", err)
		}
	}
	return payloadRoot
}

func readBackupTestExtension(t *testing.T, app *App, extensionID string) (string, string, string) {
	t.Helper()
	var installDir string
	var packagePath string
	var packageHash string
	if err := app.db.GetConn().QueryRow(`
		SELECT install_dir, package_path, package_hash
		FROM browser_extensions WHERE extension_id = ?`, extensionID).Scan(&installDir, &packagePath, &packageHash); err != nil {
		t.Fatalf("read extension returned error: %v", err)
	}
	return installDir, packagePath, packageHash
}

func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
