package browser

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func identityFixtureManifest(t *testing.T, version, description string, key []byte) []byte {
	t.Helper()
	root := map[string]any{"name": "Local identity fixture", "manifest_version": 3, "version": version, "description": description}
	if len(key) > 0 {
		root["key"] = base64.StdEncoding.EncodeToString(key)
	}
	data, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func identityFixtureDirectory(t *testing.T, manifest []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func identityFixtureZip(t *testing.T, manifest []byte) string {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	file, err := writer.Create("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.zip")
	if err := os.WriteFile(path, buffer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExtensionIdentityUpgradeRetainsSettings(t *testing.T) {
	m := newIsolationManager(t)
	key := []byte("local-public-key-fixture-a")
	manifest := identityFixtureManifest(t, "1.0", "original", key)
	first, err := m.InstallExtensionDirectory(identityFixtureDirectory(t, manifest), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ExtensionDAO.SetEnabled(first.ExtensionID, false); err != nil {
		t.Fatal(err)
	}
	if err := m.ExtensionDAO.SetDefaultInstall(first.ExtensionID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ExtensionDAO.SetProfileSettings("identity-profile", []string{first.ExtensionID}, true); err != nil {
		t.Fatal(err)
	}
	updated, err := m.InstallExtensionPackageFile(identityFixtureZip(t, identityFixtureManifest(t, "2.0", "updated description", key)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ExtensionID != first.ExtensionID || updated.InstallDir != first.InstallDir || updated.Version != "2.0" {
		t.Fatal("normal update must retain the existing management ID and installation directory")
	}
	if updated.Enabled || !updated.DefaultInstall {
		t.Fatal("upgrade changed settings")
	}
	settings, err := m.ExtensionDAO.GetProfileSettings("identity-profile")
	if err != nil || !settings.Configured || len(settings.ExtensionIDs) != 1 || settings.ExtensionIDs[0] != first.ExtensionID {
		t.Fatal("upgrade changed profile binding")
	}
	if items, err := m.ExtensionDAO.List(); err != nil || len(items) != 1 {
		t.Fatal("upgrade did not retain exactly one record")
	}
}

func TestExtensionIdentityIndependentLocalInstalls(t *testing.T) {
	for _, zipFirst := range []bool{false, true} {
		name := "directory-first"
		if zipFirst {
			name = "zip-first"
		}
		t.Run(name, func(t *testing.T) {
			m := newIsolationManager(t)
			keys := [][]byte{[]byte("identity-fixture-first"), []byte("identity-fixture-second")}
			install := func(zipInput bool, data []byte) (Extension, error) {
				if zipInput {
					return m.InstallExtensionPackageFile(identityFixtureZip(t, data), nil)
				}
				return m.InstallExtensionDirectory(identityFixtureDirectory(t, data), nil)
			}
			firstManifest := identityFixtureManifest(t, "1.0", "local", keys[0])
			first, err := install(zipFirst, firstManifest)
			if err != nil {
				t.Fatal(err)
			}
			if first.ExtensionID != extensionIDFromPublicKey(keys[0]) {
				t.Fatal("first installation did not use its public identity")
			}
			if _, err := m.ExtensionDAO.SetProfileSettings("independent-profile", []string{first.ExtensionID}, true); err != nil {
				t.Fatal(err)
			}
			second, err := install(!zipFirst, identityFixtureManifest(t, "2.0", "local", keys[1]))
			if err != nil {
				t.Fatal(err)
			}
			if second.ExtensionID != extensionIDFromPublicKey(keys[1]) || second.InstallDir == first.InstallDir {
				t.Fatal("independent installation did not receive its own identity and directory")
			}
			stored, err := m.ExtensionDAO.Get(first.ExtensionID)
			if err != nil || stored.Version != first.Version || stored.ManifestJSON != first.ManifestJSON {
				t.Fatal("first record changed")
			}
			data, err := os.ReadFile(filepath.Join(first.InstallDir, "manifest.json"))
			if err != nil || !bytes.Equal(data, firstManifest) {
				t.Fatal("first installation directory changed")
			}
			settings, err := m.ExtensionDAO.GetProfileSettings("independent-profile")
			if err != nil || !settings.Configured || len(settings.ExtensionIDs) != 1 || settings.ExtensionIDs[0] != first.ExtensionID {
				t.Fatal("first profile binding changed")
			}
			items, err := m.ExtensionDAO.List()
			if err != nil || len(items) != 2 {
				t.Fatal("expected two independent extension records")
			}
		})
	}
}

func TestExtensionIdentityLegacyUpgrade(t *testing.T) {
	for _, known := range []bool{false, true} {
		name := "add-key"
		if known {
			name = "old-hash-id-with-key"
		}
		t.Run(name, func(t *testing.T) {
			m := newIsolationManager(t)
			key := []byte("legacy-local-key")
			data := identityFixtureManifest(t, "1.0", "local", nil)
			oldID := extensionIDFromIdentityManifest(data)
			if known {
				data = identityFixtureManifest(t, "1.0", "local", key)
			}
			oldDir := filepath.Join(m.ResolveRelativePath(filepath.Join("data", extensionsRootDir)), oldID)
			if err := os.MkdirAll(oldDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(oldDir, "manifest.json"), data, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := m.ExtensionDAO.Upsert(Extension{ExtensionID: oldID, ManifestJSON: string(data), InstallDir: oldDir, Version: "1.0"}); err != nil {
				t.Fatal(err)
			}
			description := "local"
			if known {
				description = "changed"
			}
			updated, err := m.InstallExtensionDirectory(identityFixtureDirectory(t, identityFixtureManifest(t, "2.0", description, key)), nil)
			if err != nil {
				t.Fatal(err)
			}
			if updated.ExtensionID != oldID || updated.InstallDir != oldDir {
				t.Fatal("legacy upgrade migrated the management identity")
			}
			items, err := m.ExtensionDAO.List()
			if err != nil || len(items) != 1 {
				t.Fatal("legacy upgrade created duplicate record")
			}
		})
	}
}

func TestExtensionIdentityHistoricalStoreSource(t *testing.T) {
	m := newIsolationManager(t)
	key := []byte("historic-store-public-key")
	id := extensionIDFromPublicKey(key)
	legacyID := extensionIDFromManifest([]byte("historic management record"))
	manifest := identityFixtureManifest(t, "1.0", "local", nil)
	item := Extension{ExtensionID: legacyID, ManifestJSON: string(manifest), SourceURL: BuildChromeWebStoreURL(id)}
	if err := m.ExtensionDAO.Upsert(item); err != nil {
		t.Fatal(err)
	}
	storedID, err := m.storedExtensionIdentity(item, "")
	if err != nil || storedID != id {
		t.Fatal("historical store identity was lost")
	}
	updated, err := m.resolveExtensionInstallID("", identityFixtureManifest(t, "2.0", "changed", key))
	if err != nil || updated != legacyID {
		t.Fatalf("historical update = %q, %v", updated, err)
	}
	unknown, err := m.resolveExtensionInstallID("", manifest)
	if err != nil || unknown == legacyID {
		t.Fatalf("unknown installation must not select an identified record: %q, %v", unknown, err)
	}
}

func TestExtensionIdentityGeneratedPackage(t *testing.T) {
	m := newIsolationManager(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	runtimeID := extensionIDFromPublicKey(publicKey)
	packageFile := filepath.Join(t.TempDir(), "ordinary-package.crx")
	writeTestCRXPackage(t, packageFile, runtimeID, "Local identity fixture", "1.0", publicKey)
	data, original := readIdentityTestPackage(t, packageFile)
	item, err := m.InstallExtensionDirectory(identityFixtureDirectory(t, original), nil)
	if err != nil {
		t.Fatal(err)
	}
	// Model an older row, before installers stored their input provenance.
	item.installEvidence = nil
	item.PackagePath, item.PackageHash, err = m.storeExtensionPackage(item.ExtensionID, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ExtensionDAO.Upsert(item); err != nil {
		t.Fatal(err)
	}
	pemPath := strings.TrimSuffix(item.PackagePath, ".crx") + ".pem"
	unrelatedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	writeKey := func(key *rsa.PrivateKey) {
		t.Helper()
		encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		if err := os.WriteFile(pemPath, encoded, 0o600); err != nil {
			t.Fatal("cannot write test pack key")
		}
	}
	writeKey(unrelatedKey)
	if _, err := m.storedExtensionIdentity(item, ""); err == nil {
		t.Fatal("unrelated leftover PEM did not leave the package ambiguous")
	}
	if _, err := m.resolveExtensionInstallID("", original); err == nil {
		t.Fatal("ambiguous package should block weak matching when the fallback ID is occupied")
	}
	newIdentity, err := m.resolveExtensionInstallID("", original, extensionIDFromPublicKey([]byte("unrelated incoming fixture")))
	if err != nil || newIdentity == item.ExtensionID {
		t.Fatal("ambiguous package should not be weakly matched by an identified input")
	}
	writeKey(key)
	if got, err := m.storedExtensionIdentity(item, ""); err != nil || got != "" {
		t.Fatal("generated package supplied an external identity or blocked the proven keyless record")
	}
	changed := identityFixtureManifest(t, "2.0", "different shape", publicKey)
	if got, err := m.resolveExtensionInstallID("", changed); err != nil || got != runtimeID || got == item.ExtensionID {
		t.Fatal("generated runtime identity should not match an identified install with a different shape")
	}
	if got, err := m.resolveExtensionInstallID("", original); err != nil || got != item.ExtensionID {
		t.Fatal("proven generated package blocked a unique keyless upgrade")
	}

	t.Run("retained-cache-with-generated-receipt", func(t *testing.T) {
		portable := item
		originID := extensionIDFromPublicKey([]byte("independent fixture store origin"))
		portable.SourceURL = BuildChromeWebStoreURL(originID)
		portable.PackagePath = ""
		root := m.ResolveRelativePath(filepath.Join("data", extensionsRootDir))
		if ok, err := VerifyRetainedExtensionCache(portable, root); ok || err == nil {
			t.Fatal("destination cache and pack key alone established portable provenance")
		}
		// Model the durable record emitted by runtime packaging, without
		// invoking Chrome. The CRX itself is the same ordinary keyless pack.
		var err error
		portable.ManifestJSON, err = encodeExtensionManifestRecord(portable.ManifestJSON, &extensionInstallEvidence{
			FromInstaller: true, Identity: originID, GeneratedHash: portable.PackageHash,
		})
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := VerifyRetainedExtensionCache(portable, root); !ok || err != nil {
			t.Fatalf("recorded generated cache was not verified: %v", err)
		}
	})

	// The same harmless keyless archive can be the runtime cache of a row
	// with an independently known store identity. Only the local installed
	// copy is removed; the archive and matching pack key remain intact.
	t.Run("known-origin-missing-installed-manifest", func(t *testing.T) {
		known := item
		originalKey := []byte("ordinary independent origin")
		known.SourceURL = BuildChromeWebStoreURL(extensionIDFromPublicKey(originalKey))
		if err := m.ExtensionDAO.Upsert(known); err != nil {
			t.Fatal(err)
		}
		manifestPath := filepath.Join(known.InstallDir, "manifest.json")
		if err := os.WriteFile(manifestPath, identityFixtureManifest(t, "1.0", "conflicting disk copy", nil), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := m.storedExtensionIdentity(known, ""); err == nil {
			t.Fatal("generated package did not detect an existing conflicting install manifest")
		}
		if err := os.Remove(manifestPath); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.WriteFile(manifestPath, original, 0o644); err != nil {
				t.Error(err)
			}
		})
		writeKey(unrelatedKey)
		if _, err := m.storedExtensionIdentity(known, ""); err == nil {
			t.Fatal("missing installed manifest did not excuse an unrelated pack key")
		}
		writeKey(key)
		bindIdentityRecoveryFixture(t, m, known)
		updated, err := m.InstallExtensionDirectory(identityFixtureDirectory(t, identityFixtureManifest(t, "2.0", "changed", originalKey)), nil)
		assertIdentityRecoveryUpgrade(t, m, known, updated, err)
	})

	item.PackagePath, item.PackageHash = "", ""
	if err := m.ExtensionDAO.Upsert(item); err != nil {
		t.Fatal(err)
	}
	if got, err := m.storedExtensionIdentity(item, ""); err != nil || got != "" {
		t.Fatal("unreferenced leftover CRX and PEM should not affect identity")
	}
}

func readIdentityTestPackage(t *testing.T, path string) (data, original []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read test package")
	}
	archive, err := normalizeExtensionArchiveData(data)
	if err != nil {
		t.Fatal(err)
	}
	original, err = readExtensionManifestFromZip(archive)
	if err != nil {
		t.Fatal(err)
	}
	return data, original
}

func TestExtensionIdentityUnambiguousSelection(t *testing.T) {
	key := []byte("selection-public-key")
	knownID := extensionIDFromPublicKey(key)
	manifest := identityFixtureManifest(t, "1.0", "local", nil)
	keyed := identityFixtureManifest(t, "2.0", "local", key)
	weakID := extensionIDFromIdentityManifest(manifest)
	otherID := extensionIDFromManifest([]byte("second management record"))
	for _, tc := range []struct {
		name      string
		rows      []Extension
		input     []byte
		want      string
		wantError bool
	}{
		{name: "strong-before-weak", rows: []Extension{{ExtensionID: weakID, ManifestJSON: string(manifest)}, {ExtensionID: otherID, ManifestJSON: string(keyed)}}, input: keyed, want: otherID},
		{name: "ambiguous-legacy", rows: []Extension{{ExtensionID: weakID, ManifestJSON: string(manifest)}, {ExtensionID: otherID, ManifestJSON: string(manifest)}}, input: keyed, want: knownID},
		{name: "ambiguous-unknown", rows: []Extension{{ExtensionID: weakID, ManifestJSON: string(manifest)}, {ExtensionID: otherID, ManifestJSON: string(manifest)}}, input: manifest, wantError: true},
		{name: "occupied-fallback", rows: []Extension{{ExtensionID: weakID, ManifestJSON: string(keyed)}}, input: manifest, wantError: true},
		{name: "duplicate-known", rows: []Extension{{ExtensionID: weakID, ManifestJSON: string(keyed)}, {ExtensionID: otherID, ManifestJSON: string(keyed)}}, input: keyed, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newIsolationManager(t)
			for _, row := range tc.rows {
				if err := m.ExtensionDAO.Upsert(row); err != nil {
					t.Fatal(err)
				}
			}
			got, err := m.resolveExtensionInstallID("", tc.input)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected explicit selection error")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("selection = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// Exercise the historical metadata distinction without building a CRX with differing identities.
func TestExtensionIdentityOriginalManifestMetadata(t *testing.T) {
	original := identityFixtureManifest(t, "1.0", "local", nil)
	packageID := extensionIDFromPublicKey([]byte("ordinary-package-public-key"))
	localPublicKey := []byte("historical-local-manifest-public-key")
	installDir := identityFixtureDirectory(t, original)
	installed, err := ensureExtensionManifestKey(installDir, localPublicKey)
	if err != nil || installed == nil {
		t.Fatalf("local manifest augmentation failed: %v", err)
	}
	for _, storeID := range []string{"", packageID} {
		got, err := originalCRXManifestIdentity(original, installed, localPublicKey, storeID, packageID)
		if err != nil || got != packageID {
			t.Fatalf("original package metadata identity = %q, %v", got, err)
		}
	}
	// No augmentation evidence means the historical discrepancy remains unresolved.
	if _, err := originalCRXManifestIdentity(original, installed, nil, packageID, packageID); err == nil {
		t.Fatal("missing local augmentation evidence should not resolve a historical discrepancy")
	}
	if _, err := originalCRXManifestIdentity(original, append(bytes.Clone(installed), '\n'), localPublicKey, "", packageID); err == nil {
		t.Fatal("the installed manifest must be the exact augmentation")
	}
	conflictingOriginal := identityFixtureManifest(t, "1.0", "local", localPublicKey)
	if _, err := originalCRXManifestIdentity(conflictingOriginal, installed, localPublicKey, "", packageID); err == nil {
		t.Fatal("historical recovery must not reconcile an original manifest identity conflict")
	}
	if _, err := originalCRXManifestIdentity(original, installed, localPublicKey, extensionIDFromPublicKey(localPublicKey), packageID); err == nil {
		t.Fatal("historical recovery must not reconcile a store and package identity conflict")
	}
}

func TestExtensionIdentityRepeatedPackageUpgrade(t *testing.T) {
	m := newIsolationManager(t)
	key := []byte("ordinary-package-key")
	id := extensionIDFromPublicKey(key)
	source := filepath.Join(t.TempDir(), "ordinary.crx")
	writeTestCRXPackage(t, source, id, "Local identity fixture", "1.0", key)
	first, err := m.InstallExtensionPackageFile(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ExtensionDAO.SetProfileSettings("package-upgrade-profile", []string{first.ExtensionID}, true); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"2.0", "3.0"} {
		writeTestCRXPackage(t, source, id, "Local identity fixture", version, key)
		updated, err := m.InstallExtensionPackageFile(source, nil)
		if err != nil {
			t.Fatal(err)
		}
		if updated.ExtensionID != first.ExtensionID || updated.InstallDir != first.InstallDir || updated.PackagePath != first.PackagePath || updated.Version != version {
			t.Fatal("package upgrade did not retain the existing installation")
		}
	}
	settings, err := m.ExtensionDAO.GetProfileSettings("package-upgrade-profile")
	if err != nil || !settings.Configured || len(settings.ExtensionIDs) != 1 || settings.ExtensionIDs[0] != first.ExtensionID {
		t.Fatal("package upgrade changed the profile binding")
	}
	if items, err := m.ExtensionDAO.List(); err != nil || len(items) != 1 {
		t.Fatal("package upgrade did not retain exactly one record")
	}
}

func TestExtensionIdentityDirectoryWithCRXSuffix(t *testing.T) {
	m := newIsolationManager(t)
	sourceDir := filepath.Join(t.TempDir(), "ordinary-directory.crx")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(sourceDir, "manifest.json")
	if err := os.WriteFile(manifestPath, identityFixtureManifest(t, "1.0", "local", nil), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := m.InstallExtensionDirectory(sourceDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ExtensionDAO.SetProfileSettings("suffix-directory-profile", []string{first.ExtensionID}, true); err != nil {
		t.Fatal(err)
	}
	movedDir := filepath.Join(filepath.Dir(sourceDir), "moved-directory")
	if err := os.Rename(sourceDir, movedDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(movedDir, "manifest.json"), identityFixtureManifest(t, "2.0", "local", nil), 0o644); err != nil {
		t.Fatal(err)
	}
	updated, err := m.InstallExtensionDirectory(movedDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ExtensionID != first.ExtensionID || updated.InstallDir != first.InstallDir || updated.Version != "2.0" {
		t.Fatal("ordinary directory upgrade changed the installation identity")
	}
	settings, err := m.ExtensionDAO.GetProfileSettings("suffix-directory-profile")
	if err != nil || !settings.Configured || len(settings.ExtensionIDs) != 1 || settings.ExtensionIDs[0] != first.ExtensionID {
		t.Fatal("directory upgrade changed the profile binding")
	}
	if items, err := m.ExtensionDAO.List(); err != nil || len(items) != 1 {
		t.Fatal("directory upgrade did not retain exactly one record")
	}
}

func TestExtensionIdentityZIPWithCRXSuffix(t *testing.T) {
	m := newIsolationManager(t)
	zipPath := identityFixtureZip(t, identityFixtureManifest(t, "1.0", "local", nil))
	source := filepath.Join(filepath.Dir(zipPath), "ordinary-archive.crx")
	if err := os.Rename(zipPath, source); err != nil {
		t.Fatal(err)
	}
	first, err := m.InstallExtensionPackageFile(source, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The old path can now refer to a different type of input altogether.
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("unrelated local file"), 0o644); err != nil {
		t.Fatal(err)
	}
	updated, err := m.InstallExtensionPackageFile(identityFixtureZip(t, identityFixtureManifest(t, "2.0", "local", nil)), nil)
	if err != nil || updated.ExtensionID != first.ExtensionID || updated.InstallDir != first.InstallDir || updated.Version != "2.0" {
		t.Fatalf("ZIP upgrade did not retain the existing installation: %v", err)
	}
}

func TestExtensionIdentityHistoricalCRXWithoutSource(t *testing.T) {
	for _, keylessRecord := range []bool{true, false} {
		name := "augmented-record"
		if keylessRecord {
			name = "keyless-record"
		}
		t.Run(name, func(t *testing.T) {
			m := newIsolationManager(t)
			key := []byte("ordinary-historical-package-key")
			id := extensionIDFromPublicKey(key)
			source := filepath.Join(t.TempDir(), "ordinary-package.zip")
			writeTestCRXPackage(t, source, id, "Local identity fixture", "1.0", key)
			_, original := readIdentityTestPackage(t, source)
			// Seed the management ID used by the old shape matcher.
			first, err := m.InstallExtensionDirectory(identityFixtureDirectory(t, original), nil)
			if err != nil {
				t.Fatal(err)
			}
			firstPackage, err := m.InstallExtensionPackageFile(source, nil)
			if err != nil || firstPackage.ExtensionID != first.ExtensionID || firstPackage.ExtensionID == id {
				t.Fatalf("fixture did not retain the legacy management ID: %v", err)
			}
			if _, err := m.ExtensionDAO.SetProfileSettings("historic-package-profile", []string{first.ExtensionID}, true); err != nil {
				t.Fatal(err)
			}
			if keylessRecord {
				// An old row can still contain the original manifest, while the
				// installed copy contains the importer's exact local augmentation.
				firstPackage.ManifestJSON = string(original)
				firstPackage.installEvidence = nil
				if err := m.ExtensionDAO.Upsert(firstPackage); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(source); err != nil {
				t.Fatal(err)
			}
			got, err := m.storedExtensionIdentity(firstPackage, "")
			if err != nil || got != id {
				t.Fatalf("historical augmentation must use retained package evidence: %v", err)
			}
			badDigest := firstPackage
			badDigest.PackageHash = strings.Repeat("0", 64)
			if _, err := m.storedExtensionIdentity(badDigest, ""); err == nil {
				t.Fatal("an invalid package digest must not establish historical identity")
			}

			otherKey := []byte("independent-historical-package-key")
			otherPath := filepath.Join(t.TempDir(), "independent.zip")
			writeTestCRXPackage(t, otherPath, extensionIDFromPublicKey(otherKey), "Local identity fixture", "1.0", otherKey)
			other, err := m.InstallExtensionPackageFile(otherPath, nil)
			if err != nil || other.ExtensionID == first.ExtensionID || other.InstallDir == first.InstallDir {
				t.Fatalf("independent ext should not reuse the historical installation: %v", err)
			}
			updatePath := filepath.Join(t.TempDir(), "ordinary-update.zip")
			writeTestCRXPackage(t, updatePath, id, "Updated local identity fixture", "2.0", key)
			updated, err := m.InstallExtensionPackageFile(updatePath, nil)
			if err != nil || updated.ExtensionID != first.ExtensionID || updated.InstallDir != first.InstallDir || updated.Version != "2.0" {
				t.Fatalf("historical CRX upgrade did not retain the existing installation: %v", err)
			}
			settings, err := m.ExtensionDAO.GetProfileSettings("historic-package-profile")
			if err != nil || !settings.Configured || len(settings.ExtensionIDs) != 1 || settings.ExtensionIDs[0] != first.ExtensionID {
				t.Fatal("historical upgrade changed the profile binding")
			}
			items, err := m.ExtensionDAO.List()
			if err != nil || len(items) != 2 {
				t.Fatal("historical upgrade and independent installation must retain exactly two records")
			}
		})
	}
}

func TestExtensionIdentityRestoredWithoutPackageReference(t *testing.T) {
	for _, tc := range []struct {
		name      string
		installed func(t *testing.T, key []byte) []byte
	}{
		{name: "disk-only-key", installed: func(t *testing.T, key []byte) []byte {
			original := identityFixtureManifest(t, "1.0", "local", nil)
			data, err := ensureExtensionManifestKey(identityFixtureDirectory(t, original), key)
			if err != nil || data == nil {
				t.Fatalf("prepare recovered manifest: %v", err)
			}
			return data
		}},
		{name: "unexplained-contents", installed: func(t *testing.T, _ []byte) []byte {
			return identityFixtureManifest(t, "1.0", "different contents", nil)
		}},
		{name: "empty-file", installed: func(t *testing.T, _ []byte) []byte { return []byte{} }},
		{name: "invalid-manifest", installed: func(t *testing.T, _ []byte) []byte { return []byte("{}") }},
		{name: "genuine-legacy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newIsolationManager(t)
			original := identityFixtureManifest(t, "1.0", "local", nil)
			key := []byte("ordinary restored key")
			first, err := m.InstallExtensionDirectory(identityFixtureDirectory(t, original), nil)
			if err != nil {
				t.Fatal(err)
			}
			// Model the restored row at the DAO boundary: backup repair cleared
			// both package fields and the managed installation was retained.
			if tc.installed != nil {
				data := tc.installed(t, key)
				if err := os.WriteFile(filepath.Join(first.InstallDir, "manifest.json"), data, 0o644); err != nil {
					t.Fatal(err)
				}
				candidate := identityFixtureManifest(t, "2.0", "local", key)
				if got, err := m.resolveExtensionInstallID("", candidate); err != nil || got != extensionIDFromPublicKey(key) {
					t.Fatalf("unproven restored row was not kept separate: got existing=%t, err=%v", got == first.ExtensionID, err)
				}
				if _, err := m.resolveExtensionInstallID("", original); err == nil {
					t.Fatal("unproven restored row was eligible for a keyless upgrade")
				}
				return
			}
			bindIdentityRecoveryFixture(t, m, first)
			candidate := identityFixtureManifest(t, "2.0", "local", key)
			updated, err := m.InstallExtensionPackageFile(identityFixtureZip(t, candidate), nil)
			assertIdentityRecoveryUpgrade(t, m, first, updated, err)
		})
	}
}

func TestExtensionIdentityUpgradeWithMissingArtifact(t *testing.T) {
	for _, name := range []string{"keyed-local-missing-package", "store-missing-package", "store-missing-package-keyless-record", "store-missing-both", "import-missing-installed-manifest", "import-missing-install-directory"} {
		t.Run(name, func(t *testing.T) {
			m := newIsolationManager(t)
			key := []byte("ordinary recovery key")
			id := extensionIDFromPublicKey(key)
			source := filepath.Join(t.TempDir(), "ordinary.crx")
			writeTestCRXPackage(t, source, id, "Local identity fixture", "1.0", key)
			data, original := readIdentityTestPackage(t, source)
			first, err := m.InstallExtensionDirectory(identityFixtureDirectory(t, original), nil)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "keyed-local-missing-package":
				// Use an ordinary keyed ZIP, then model a stale reference left by
				// an earlier cache operation. The original ZIP is not available.
				keyed := []byte(`{"key":"` + extensionManifestKey(key) + `","name":"Local identity fixture","version":"1.0"}`)
				zipPath := identityFixtureZip(t, keyed)
				first, err = m.InstallExtensionPackageFile(zipPath, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(zipPath); err != nil {
					t.Fatal(err)
				}
				first.PackagePath, first.PackageHash, err = m.storeExtensionPackage(first.ExtensionID, data)
				if err != nil {
					t.Fatal(err)
				}
				if err := m.ExtensionDAO.Upsert(first); err != nil {
					t.Fatal(err)
				}
			case "store-missing-package", "store-missing-package-keyless-record", "store-missing-both":
				first, err = m.InstallExtensionPackageBytes(id, BuildChromeWebStoreURL(id), data, nil)
				if err == nil && name == "store-missing-package-keyless-record" {
					first.ManifestJSON = string(original)
					first.installEvidence = nil
					err = m.ExtensionDAO.Upsert(first)
				}
			default:
				first, err = m.InstallExtensionPackageFile(source, nil)
			}
			if err != nil || first.ExtensionID == id || first.PackagePath == "" {
				t.Fatalf("fixture did not retain a separate management ID and package reference: %v", err)
			}
			if err := os.Remove(source); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(name, "missing-package") || name == "store-missing-both" {
				if err := os.Remove(first.PackagePath); err != nil {
					t.Fatal(err)
				}
			}
			if strings.Contains(name, "missing-install") || name == "store-missing-both" {
				if err := os.Remove(filepath.Join(first.InstallDir, "manifest.json")); err != nil {
					t.Fatal(err)
				}
			}
			if name == "import-missing-install-directory" {
				if err := os.Remove(first.InstallDir); err != nil {
					t.Fatal(err)
				}
			}
			bindIdentityRecoveryFixture(t, m, first)
			updated, err := m.InstallExtensionDirectory(identityFixtureDirectory(t, identityFixtureManifest(t, "2.0", "changed", key)), nil)
			assertIdentityRecoveryUpgrade(t, m, first, updated, err)
		})
	}
}

func TestExtensionIdentityUnprovenOrConflictingRecovery(t *testing.T) {
	for _, name := range []string{"missing-package-copied-augmentation", "missing-package-store-conflict", "missing-package-keyless", "present-package-conflicting-installed", "present-package-invalid-installed", "present-package-cleared-install-path", "present-package-keyless-without-augmentation", "invalid-reference", "partial-path", "partial-digest", "invalid-digest", "mismatching-digest", "nonregular-package"} {
		t.Run(name, func(t *testing.T) {
			m := newIsolationManager(t)
			key := []byte("ordinary recorded key")
			id := extensionIDFromPublicKey(key)
			source := filepath.Join(t.TempDir(), "ordinary.crx")
			writeTestCRXPackage(t, source, id, "Local identity fixture", "1.0", key)
			data, original := readIdentityTestPackage(t, source)
			first, err := m.InstallExtensionPackageBytes(id, BuildChromeWebStoreURL(id), data, nil)
			if err != nil {
				t.Fatal(err)
			}
			// These cases exercise rows from installers that left only copies.
			first.installEvidence = nil
			manifestPath := filepath.Join(first.InstallDir, "manifest.json")
			switch name {
			case "missing-package-copied-augmentation", "missing-package-keyless", "missing-package-store-conflict":
				if err := os.Remove(first.PackagePath); err != nil {
					t.Fatal(err)
				}
				first.SourceURL = ""
				if name == "missing-package-store-conflict" {
					first.SourceURL = BuildChromeWebStoreURL(extensionIDFromPublicKey([]byte("separate recognized store ID")))
				}
				if name == "missing-package-keyless" {
					first.ManifestJSON = string(original)
					if err := os.WriteFile(manifestPath, original, 0o644); err != nil {
						t.Fatal(err)
					}
				}
			case "present-package-conflicting-installed", "present-package-invalid-installed", "present-package-cleared-install-path":
				// Recorded original + store + package used to return early.
				first.ManifestJSON = string(original)
				if name == "present-package-cleared-install-path" {
					first.InstallDir = ""
				}
				conflicting := identityFixtureManifest(t, "1.0", "different installed content", key)
				if name == "present-package-invalid-installed" {
					conflicting = []byte("not a manifest")
				}
				if err := os.WriteFile(manifestPath, conflicting, 0o644); err != nil {
					t.Fatal(err)
				}
			case "present-package-keyless-without-augmentation":
				first.SourceURL, first.ManifestJSON = "", string(original)
				if err := os.Remove(manifestPath); err != nil {
					t.Fatal(err)
				}
			case "invalid-reference":
				first.PackagePath = filepath.Join(t.TempDir(), "missing.crx")
			case "partial-path":
				first.PackageHash = ""
			case "partial-digest":
				first.PackagePath = ""
			case "invalid-digest":
				if err := os.Remove(first.PackagePath); err != nil {
					t.Fatal(err)
				}
				first.PackageHash = "invalid digest"
			case "mismatching-digest":
				first.PackageHash = strings.Repeat("0", 64)
			case "nonregular-package":
				if err := os.Remove(first.PackagePath); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(first.PackagePath, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.ExtensionDAO.Upsert(first); err != nil {
				t.Fatal(err)
			}
			if _, err := m.storedExtensionIdentity(first, ""); err == nil {
				t.Fatal("ambiguous or conflicting evidence was accepted")
			}
			if _, err := m.resolveExtensionInstallID("", identityFixtureManifest(t, "2.0", "changed", key)); err == nil {
				t.Fatal("resolution accepted conflicting or unproven evidence for an occupied ID")
			}
		})
	}
}

func bindIdentityRecoveryFixture(t *testing.T, m *Manager, first Extension) {
	t.Helper()
	if _, err := m.ExtensionDAO.SetProfileSettings("recovery-profile", []string{first.ExtensionID}, true); err != nil {
		t.Fatal(err)
	}
}

func assertIdentityRecoveryUpgrade(t *testing.T, m *Manager, first, updated Extension, err error) {
	t.Helper()
	if err != nil || updated.ExtensionID != first.ExtensionID || updated.InstallDir != first.InstallDir || updated.Version != "2.0" {
		t.Fatalf("recovery did not update the original ID and directory: %v", err)
	}
	if items, err := m.ExtensionDAO.List(); err != nil || len(items) != 1 {
		t.Fatal("recovery did not retain exactly one record")
	}
	if data, err := os.ReadFile(filepath.Join(first.InstallDir, "manifest.json")); err != nil || string(data) != updated.ManifestJSON {
		t.Fatal("recovery did not write the upgraded manifest to the original directory")
	}
	settings, err := m.ExtensionDAO.GetProfileSettings("recovery-profile")
	if err != nil || !settings.Configured || len(settings.ExtensionIDs) != 1 || settings.ExtensionIDs[0] != first.ExtensionID {
		t.Fatal("recovery did not preserve the profile binding")
	}
}

func TestExtensionIdentityRejectsInvalidKey(t *testing.T) {
	m := newIsolationManager(t)
	data := []byte(`{"name":"Local fixture","version":"1.0","manifest_version":3,"key":"invalid encoding"}`)
	if _, err := m.InstallExtensionDirectory(identityFixtureDirectory(t, data), nil); err == nil {
		t.Fatal("invalid key should be rejected")
	}
	if items, err := m.ExtensionDAO.List(); err != nil || len(items) != 0 {
		t.Fatal("invalid input created a record")
	}
}
