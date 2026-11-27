package backend

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ant-chrome/backend/internal/backup"
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
)

func newExtensionRestoreTestApp(t *testing.T) *App {
	t.Helper()
	a := newBackupExtensionRepairTestApp(t)
	a.config = config.DefaultConfig()
	a.config.Browser.UserDataRoot = filepath.Join(a.appRoot, "user-data")
	a.browserMgr = browser.NewManager(a.config, a.appRoot)
	conn := a.db.GetConn()
	a.browserMgr.ProfileDAO = browser.NewSQLiteProfileDAO(conn)
	a.browserMgr.ProxyDAO = browser.NewSQLiteProxyDAO(conn)
	a.browserMgr.CoreDAO = browser.NewSQLiteCoreDAO(conn)
	a.browserMgr.GroupDAO = browser.NewSQLiteGroupDAO(conn)
	a.browserMgr.ExtensionDAO = browser.NewSQLiteExtensionDAO(conn)
	a.browserMgr.BookmarkDAO = browser.NewSQLiteBookmarkDAO(conn)
	if err := a.config.Save(filepath.Join(a.appRoot, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.backupStopRuntimeForMaintenance() })
	return a
}

func writeExtensionRestoreFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func installExtensionRestoreDirectory(t *testing.T, a *App, name, version, key string) browser.Extension {
	t.Helper()
	ext, err := a.browserMgr.InstallExtensionDirectory(backupIdentityDirectory(t, backupIdentityManifest(t, name, version, key)), nil)
	if err != nil {
		t.Fatal(err)
	}
	return ext
}

func bindExtensionRestoreProfile(t *testing.T, a *App, id string, extensions ...string) browser.Profile {
	t.Helper()
	p := browser.Profile{ProfileId: id, ProfileName: "Restore fixture profile", UserDataDir: id}
	if err := a.browserMgr.ProfileDAO.Upsert(&p); err != nil {
		t.Fatal(err)
	}
	if _, err := a.browserMgr.ExtensionDAO.SetProfileSettings(id, extensions, true); err != nil {
		t.Fatal(err)
	}
	writeExtensionRestoreFixture(t, filepath.Join(a.browserMgr.ResolveUserDataDir(&p), "fixture.txt"), []byte(id))
	return p
}

func writeFullExtensionRestorePackage(t *testing.T, a *App, path string) {
	t.Helper()
	if _, err := a.db.GetConn().Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	scope := backup.Scope{Format: backup.PackageFormat, ManifestVersion: backup.ManifestVersion, AppRoot: a.appRoot, Entries: []backup.ScopeEntry{
		{ID: "database_sqlite_main", Category: backup.CategoryAppData, EntryType: backup.EntryTypeFile, Required: true, SourcePath: filepath.Join(a.appRoot, "data", "app.db"), ArchivePath: "payload/app/database/app.db"},
		{ID: "app_data_root", Category: backup.CategoryAppData, EntryType: backup.EntryTypeDir, Required: true, SourcePath: filepath.Join(a.appRoot, "data", "extensions"), ArchivePath: "payload/app/data/extensions/"},
		{ID: "browser_user_data_root", Category: backup.CategoryAppData, EntryType: backup.EntryTypeDir, SourcePath: a.config.Browser.UserDataRoot, ArchivePath: "payload/browser/user-data/"},
	}}
	if _, _, _, err := backupWritePackageZip(path, scope, backup.BuildManifest(scope, "test", "1", time.Unix(0, 0)), nil); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionRestoreSameManagementID(t *testing.T) {
	for _, route := range []string{"full", "profile"} {
		for _, identity := range []string{"different", "unproven", "same", "builtin", "builtin-label-only"} {
			t.Run(route+"/"+identity, func(t *testing.T) {
				source, target := newExtensionRestoreTestApp(t), newExtensionRestoreTestApp(t)
				const name = "Collision fixture"
				var src, dst browser.Extension
				if strings.HasPrefix(identity, "builtin") {
					for _, a := range []*App{source, target} {
						if err := a.browserMgr.SyncBuiltinExtensions(); err != nil {
							t.Fatal(err)
						}
					}
					rows, err := source.browserMgr.ExtensionDAO.List()
					if err != nil || len(rows) != 1 || !strings.HasPrefix(rows[0].SourceURL, "builtin://") {
						t.Fatalf("startup did not register a builtin: %v", err)
					}
					src = rows[0]
					dst, err = target.browserMgr.ExtensionDAO.Get(src.ExtensionID)
					if err != nil {
						t.Fatal(err)
					}
					if identity == "builtin-label-only" {
						manifest := backupIdentityManifest(t, "Unrelated fixture", "1.0", "")
						src.ManifestJSON = string(manifest)
						writeExtensionRestoreFixture(t, filepath.Join(src.InstallDir, "manifest.json"), manifest)
						if err := source.browserMgr.ExtensionDAO.Upsert(src); err != nil {
							t.Fatal(err)
						}
					}
				} else {
					src = installExtensionRestoreDirectory(t, source, name, "1.0", "")
					dst = installExtensionRestoreDirectory(t, target, name, "1.0", "")
					if identity != "unproven" {
						key := base64.StdEncoding.EncodeToString([]byte("same restore fixture key"))
						src = installExtensionRestoreDirectory(t, source, name, "2.0", key)
						if identity == "different" {
							key = base64.StdEncoding.EncodeToString([]byte("different restore fixture key"))
						}
						dst = installExtensionRestoreDirectory(t, target, name, "3.0", key)
					}
				}
				if src.ExtensionID != dst.ExtensionID {
					t.Fatal("fixture did not retain the common management ID")
				}
				if err := target.browserMgr.ExtensionDAO.SetEnabled(dst.ExtensionID, false); err != nil {
					t.Fatal(err)
				}
				if err := target.browserMgr.ExtensionDAO.SetDefaultInstall(dst.ExtensionID, true); err != nil {
					t.Fatal(err)
				}
				manifestPath := filepath.Join(dst.InstallDir, "manifest.json")
				wantManifest, err := os.ReadFile(manifestPath)
				if err != nil {
					t.Fatal(err)
				}
				writeExtensionRestoreFixture(t, filepath.Join(src.InstallDir, "source-only.txt"), []byte("source-only"))
				other := installExtensionRestoreDirectory(t, source, "Noncolliding restore fixture", "1.0", "")
				p := bindExtensionRestoreProfile(t, source, "incoming", src.ExtensionID, other.ExtensionID)
				targetProfile := bindExtensionRestoreProfile(t, target, "existing", dst.ExtensionID)
				zipPath := filepath.Join(t.TempDir(), "restore.zip")
				wantConflict := identity != "same" && identity != "builtin"
				var importErr error
				if route == "full" {
					writeFullExtensionRestorePackage(t, source, zipPath)
					var result map[string]interface{}
					result, importErr = target.backupImportFromPathLocked(zipPath)
					if result["rolledBack"] == true {
						t.Errorf("full backup unexpectedly reported rollback: %v", result["failedComponents"])
					}
				} else {
					if _, err := source.writeProfilePackage(zipPath, []browser.Profile{p}); err != nil {
						t.Fatal(err)
					}
					mode := profilePackageImportModeNew
					if wantConflict {
						mode = profilePackageImportModeOverwrite
					}
					_, importErr = target.importProfilePackageFromPathWithMode(zipPath, mode)
				}
				if wantConflict {
					if importErr == nil || !strings.Contains(importErr.Error(), "插件身份冲突") || !strings.Contains(importErr.Error(), src.ExtensionID) {
						t.Errorf("expected explicit extension identity conflict for %s, got %v", src.ExtensionID, importErr)
					}
					if _, err := os.Stat(filepath.Join(target.appRoot, "data", "extensions", other.ExtensionID)); !os.IsNotExist(err) {
						t.Error("failed restore left a noncolliding extension directory")
					}
					userDataRoot := target.config.Browser.UserDataRoot
					entries, err := os.ReadDir(userDataRoot)
					if err != nil {
						t.Fatal(err)
					}
					for _, entry := range entries {
						switch entry.Name() {
						case targetProfile.UserDataDir:
							data, err := os.ReadFile(filepath.Join(userDataRoot, entry.Name(), "fixture.txt"))
							if err != nil || string(data) != targetProfile.ProfileId {
								t.Errorf("old profile data changed: %v", err)
							}
						case ".imports":
							batches, err := os.ReadDir(filepath.Join(userDataRoot, entry.Name()))
							if err != nil || len(batches) != 0 {
								t.Errorf("failed restore left staged data: %v", err)
							}
						default:
							t.Errorf("failed restore left a new data directory: %s", entry.Name())
						}
					}
					if _, err := os.Stat(filepath.Join(userDataRoot, targetProfile.UserDataDir, "fixture.txt")); err != nil {
						t.Errorf("failed restore removed the old profile data: %v", err)
					}
					if _, err := target.browserMgr.ExtensionDAO.Get(other.ExtensionID); err == nil {
						t.Error("failed restore committed an unrelated source extension row")
					}
				} else if importErr != nil {
					t.Fatalf("proven identity did not restore: %v", importErr)
				}
				profiles, err := target.browserMgr.ProfileDAO.List()
				if err != nil {
					t.Fatal(err)
				}
				wantProfiles := 2
				if wantConflict {
					wantProfiles = 1
				}
				if len(profiles) != wantProfiles {
					t.Errorf("active profile count = %d, want %d", len(profiles), wantProfiles)
				}
				var bindings int
				if err := target.db.GetConn().QueryRow("SELECT COUNT(*) FROM browser_profile_extensions WHERE extension_id = ?", dst.ExtensionID).Scan(&bindings); err != nil || bindings != wantProfiles {
					t.Errorf("total bindings to the reused ID = %d, want %d: %v", bindings, wantProfiles, err)
				}
				old, err := target.browserMgr.ProfileDAO.GetById(targetProfile.ProfileId)
				if err != nil || old.DeletedAt != "" {
					t.Errorf("existing profile was not preserved: %v", err)
				}
				stored, err := target.browserMgr.ExtensionDAO.Get(dst.ExtensionID)
				if err != nil || stored.Version != dst.Version || stored.Enabled || !stored.DefaultInstall || stored.InstallDir != dst.InstallDir || stored.PackagePath != dst.PackagePath || stored.PackageHash != dst.PackageHash {
					t.Errorf("destination extension row was changed: %v", err)
				}
				got, err := os.ReadFile(manifestPath)
				if err != nil || !bytes.Equal(got, wantManifest) {
					t.Errorf("destination manifest was changed: %v", err)
				}
				if _, err := os.Stat(filepath.Join(dst.InstallDir, "source-only.txt")); !os.IsNotExist(err) {
					t.Error("restore copied files into a reused destination extension")
				}
			})
		}
	}
}

func TestBackupImportExtensionReferencesRequireSourceRecord(t *testing.T) {
	for _, scenario := range []string{"missing-row", "missing-table"} {
		t.Run(scenario, func(t *testing.T) {
			source, target := newExtensionRestoreTestApp(t), newExtensionRestoreTestApp(t)
			key := base64.StdEncoding.EncodeToString([]byte("ordinary reference fixture key"))
			ext := installExtensionRestoreDirectory(t, target, "Target extension", "1.0", key)
			// The old backup still contains references and loose files, but no
			// extension row whose identity can authorize a destination mapping.
			writeExtensionRestoreFixture(t, filepath.Join(source.appRoot, "data", "extensions", ext.ExtensionID, "source-only.txt"), []byte("orphaned payload"))
			profile := bindExtensionRestoreProfile(t, source, "orphaned-reference", ext.ExtensionID)
			if _, err := source.db.GetConn().Exec("INSERT INTO browser_profile_extension_runtime (profile_id, extension_id) VALUES (?, ?)", profile.ProfileId, ext.ExtensionID); err != nil {
				t.Fatal(err)
			}
			if scenario == "missing-table" {
				if _, err := source.db.GetConn().Exec("DROP TABLE browser_extensions"); err != nil {
					t.Fatal(err)
				}
			}
			zipPath := filepath.Join(t.TempDir(), "restore.zip")
			writeFullExtensionRestorePackage(t, source, zipPath)
			result, err := target.backupImportFromPathLocked(zipPath)
			if err != nil || result["rolledBack"] == true {
				t.Fatalf("a missing extension reference must not abort the restore: %v", err)
			}
			if _, err := target.browserMgr.ProfileDAO.GetById(profile.ProfileId); err != nil {
				t.Fatalf("unrelated profile data did not restore: %v", err)
			}
			var bindings, runtime int
			if err := target.db.GetConn().QueryRow(
				"SELECT (SELECT COUNT(*) FROM browser_profile_extensions), (SELECT COUNT(*) FROM browser_profile_extension_runtime)",
			).Scan(&bindings, &runtime); err != nil || bindings != 0 || runtime != 0 {
				t.Errorf("orphaned source was mapped to the target (bindings=%d, runtime=%d): %v", bindings, runtime, err)
			}
			if _, err := os.Stat(filepath.Join(ext.InstallDir, "source-only.txt")); !os.IsNotExist(err) {
				t.Error("source artifact was copied into the existing extension")
			}
		})
	}
}

func TestExtensionRestoreProfilePackageRetainsVerifiedCache(t *testing.T) {
	for _, scenario := range []struct {
		name                             string
		stagedDir, existingDir, attach   bool
		legacyOriginal                   bool
		stagedManifest, existingManifest string
	}{
		{name: "install-only", stagedDir: true, attach: true},
		{name: "no-index", attach: true},
		{name: "missing"},
		{name: "wrong-digest"},
		{name: "historical-unproven"},
		{name: "source-contradiction"},
		{name: "existing-dir-match", stagedDir: true, existingDir: true, attach: true},
		{name: "staged-manifest-missing", stagedDir: true, existingDir: true, stagedManifest: "missing", attach: true},
		{name: "staged-manifest-contradiction", stagedDir: true, existingDir: true, stagedManifest: "different"},
		{name: "target-manifest-contradiction", stagedDir: true, existingDir: true, existingManifest: "different"},
		{name: "legacy-original-match", stagedDir: true, existingDir: true, legacyOriginal: true, attach: true},
		{name: "legacy-original-staged-contradiction", stagedDir: true, existingDir: true, legacyOriginal: true, stagedManifest: "different"},
		{name: "legacy-original-target-contradiction", stagedDir: true, existingDir: true, legacyOriginal: true, existingManifest: "different"},
		{name: "legacy-original-wrong-digest", stagedDir: true, existingDir: true, legacyOriginal: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			source, target := newExtensionRestoreTestApp(t), newExtensionRestoreTestApp(t)
			const name = "Retained cache fixture"
			legacy := installExtensionRestoreDirectory(t, source, name, "1.0", "")
			key := []byte("normal retained cache key")
			encodedKey := base64.StdEncoding.EncodeToString(key)
			original := backupIdentityManifest(t, name, "1.0", "")
			if scenario.legacyOriginal {
				// This normal original includes the same key as the CRX header.
				// Make it indistinguishable from augmentation without the CRX.
				var compact bytes.Buffer
				if err := json.Compact(&compact, backupIdentityManifest(t, name, "1.0", encodedKey)); err != nil {
					t.Fatal(err)
				}
				original = compact.Bytes()
			}
			cache := backupIdentityCRX(t, key, original, "retained")
			input := filepath.Join(t.TempDir(), "ordinary.crx")
			writeExtensionRestoreFixture(t, input, cache)
			first, err := source.browserMgr.InstallExtensionPackageFile(input, nil)
			if err != nil || first.ExtensionID != legacy.ExtensionID || first.PackageHash != sha256Hex(cache) {
				t.Fatalf("prepare retained cache with legacy management ID: %v", err)
			}
			if err := source.browserMgr.ExtensionDAO.SetEnabled(first.ExtensionID, false); err != nil {
				t.Fatal(err)
			}
			if err := source.browserMgr.ExtensionDAO.SetDefaultInstall(first.ExtensionID, true); err != nil {
				t.Fatal(err)
			}
			if scenario.name == "historical-unproven" || scenario.legacyOriginal {
				if _, err := source.db.GetConn().Exec("UPDATE browser_extensions SET manifest_json = ?, source_url = '' WHERE extension_id = ?", first.ManifestJSON, first.ExtensionID); err != nil {
					t.Fatal(err)
				}
			}
			if scenario.name == "source-contradiction" {
				// A canonical store record claims a different identity than the
				// durable original. It is metadata only; no request is made.
				otherStore := browser.BuildChromeWebStoreURL(backupTestExtensionIDB)
				if _, err := source.db.GetConn().Exec("UPDATE browser_extensions SET source_url = ? WHERE extension_id = ?", otherStore, first.ExtensionID); err != nil {
					t.Fatal(err)
				}
			}
			for _, path := range []string{input, first.PackagePath} {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if !scenario.stagedDir {
				if err := os.RemoveAll(first.InstallDir); err != nil {
					t.Fatal(err)
				}
			} else {
				sourceManifest := filepath.Join(first.InstallDir, "manifest.json")
				switch scenario.stagedManifest {
				case "missing":
					if err := os.Remove(sourceManifest); err != nil {
						t.Fatal(err)
					}
				case "different":
					writeExtensionRestoreFixture(t, sourceManifest, backupIdentityManifest(t, name, "1.0", base64.StdEncoding.EncodeToString([]byte("other extension key"))))
				}
				writeExtensionRestoreFixture(t, filepath.Join(first.InstallDir, "staged-only.txt"), []byte("staged artifact"))
			}
			p := bindExtensionRestoreProfile(t, source, "cache-profile", first.ExtensionID)
			archive := filepath.Join(t.TempDir(), "restore.zip")
			if _, err := source.writeProfilePackage(archive, []browser.Profile{p}); err != nil {
				t.Fatal(err)
			}
			contents, err := openProfilePackageContents(archive)
			if err != nil {
				t.Fatal(err)
			}
			artifacts := contents.DatabaseSnapshot.ExtensionArtifacts
			contents.Reader.Close()
			if scenario.stagedDir {
				if len(artifacts) != 1 || artifacts[0].PackageArchivePath != "" || artifacts[0].InstallDirArchivePath == "" {
					t.Fatal("expected only an install directory in the artifact index")
				}
			} else if len(artifacts) != 0 {
				t.Fatal("expected no extension artifact index entries")
			}
			installDir := filepath.Join(target.appRoot, "data", "extensions", first.ExtensionID)
			cachePath := filepath.Join(filepath.Dir(installDir), "packages", first.ExtensionID+".crx")
			if scenario.name == "wrong-digest" || scenario.name == "legacy-original-wrong-digest" {
				cache = backupIdentityCRX(t, key, original, "different payload, same identity")
			}
			if scenario.name != "missing" {
				writeExtensionRestoreFixture(t, cachePath, cache)
			}
			var existingProfile browser.Profile
			existingManifest := []byte(first.ManifestJSON)
			if scenario.existingDir {
				if scenario.existingManifest == "different" {
					existingManifest = backupIdentityManifest(t, name, "1.0", base64.StdEncoding.EncodeToString([]byte("other extension key")))
				}
				writeExtensionRestoreFixture(t, filepath.Join(installDir, "manifest.json"), existingManifest)
				writeExtensionRestoreFixture(t, filepath.Join(installDir, "target-only.txt"), []byte("retained artifact"))
				existingProfile = bindExtensionRestoreProfile(t, target, "existing-cache-profile", first.ExtensionID)
			}
			result, err := target.importProfilePackageFromPath(archive)
			if err != nil || result.ImportedCount != 1 {
				t.Fatalf("import portable profile: %v", err)
			}
			restored, err := target.browserMgr.ExtensionDAO.Get(first.ExtensionID)
			wantPath := ""
			if scenario.attach {
				wantPath = cachePath
			}
			if err != nil || restored.PackageHash != first.PackageHash || restored.PackagePath != wantPath {
				t.Errorf("restore retained wrong cache path or digest (attached=%v, want=%v): %v", restored.PackagePath != "", wantPath != "", err)
			}
			if wantWarning := !scenario.attach && scenario.name != "missing"; strings.Contains(strings.Join(result.Warnings, "\n"), "未恢复插件包引用") != wantWarning {
				t.Errorf("restore cache warning did not match expectation (want=%v)", wantWarning)
			}
			if scenario.existingDir {
				for path, want := range map[string][]byte{
					filepath.Join(installDir, "manifest.json"):   existingManifest,
					filepath.Join(installDir, "target-only.txt"): []byte("retained artifact"),
					cachePath: cache,
				} {
					if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
						t.Errorf("restore changed the retained %s", filepath.Base(path))
					}
				}
				if _, err := os.Stat(filepath.Join(installDir, "staged-only.txt")); !os.IsNotExist(err) {
					t.Error("restore copied staged files into the existing directory")
				}
			}
			upgraded := installExtensionRestoreDirectory(t, target, name, "2.0", encodedKey)
			wantReuse := scenario.attach || scenario.name == "missing"
			if (upgraded.ExtensionID == first.ExtensionID) != wantReuse {
				t.Error("ordinary upgrade resolved to the wrong management ID")
			}
			if wantReuse && (!backupSamePath(upgraded.InstallDir, installDir) || upgraded.Version != "2.0" || upgraded.Enabled || !upgraded.DefaultInstall) {
				t.Error("ordinary upgrade changed the restored directory or settings")
			}
			profiles, err := target.browserMgr.ProfileDAO.List()
			wantProfiles := 1
			if scenario.existingDir {
				wantProfiles++
			}
			if err != nil || len(profiles) != wantProfiles {
				t.Fatalf("find imported profile: %v", err)
			}
			for _, profile := range profiles {
				settings, err := target.browserMgr.ExtensionDAO.GetProfileSettings(profile.ProfileId)
				if err != nil || !settings.Configured || len(settings.ExtensionIDs) != 1 || settings.ExtensionIDs[0] != first.ExtensionID {
					t.Errorf("restore or ordinary install changed the profile binding (preexisting=%v): %v", profile.ProfileId == existingProfile.ProfileId, err)
				}
			}
		})
	}
}
