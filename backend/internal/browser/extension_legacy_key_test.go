package browser

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyCRX3WrongFirstProofKeyUpgrade(t *testing.T) {
	m := newIsolationManager(t)
	wrongKey := []byte("legacy-first-proof-key")
	declaredKey := []byte("declared-second-proof-key")
	storeID := extensionIDFromPublicKey(declaredKey)
	original := identityFixtureManifest(t, "1.0", "legacy store extension", nil)
	crx := crx3TestPackage(t, crx3TestHeader(crx3TestRawID(declaredKey), wrongKey, declaredKey), original)

	legacy, err := m.InstallExtensionPackageBytes(storeID, BuildChromeWebStoreURL(storeID), crx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.ExtensionID != storeID {
		t.Fatalf("initial management ID = %q, want declared store ID %q", legacy.ExtensionID, storeID)
	}
	legacyKeyManifest, err := manifestWithExtensionKey(original, extensionManifestKey(wrongKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy.InstallDir, "manifest.json"), legacyKeyManifest, 0o644); err != nil {
		t.Fatal(err)
	}
	legacy.ManifestJSON = string(legacyKeyManifest)
	legacy.installEvidence = nil // legacy rows have no installer provenance envelope
	if err := m.ExtensionDAO.SetEnabled(legacy.ExtensionID, false); err != nil {
		t.Fatal(err)
	}
	if err := m.ExtensionDAO.SetDefaultInstall(legacy.ExtensionID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ExtensionDAO.SetProfileSettings("legacy-key-profile", []string{legacy.ExtensionID}, true); err != nil {
		t.Fatal(err)
	}
	if err := m.ExtensionDAO.Upsert(legacy); err != nil {
		t.Fatal(err)
	}

	storedLegacy, err := m.ExtensionDAO.Get(legacy.ExtensionID)
	if err != nil {
		t.Fatal(err)
	}
	resolvedLegacy, identityErr := m.storedExtensionIdentity(storedLegacy, storeID)
	if identityErr != nil || resolvedLegacy != storeID {
		t.Fatalf("stored legacy identity = %q, %v", resolvedLegacy, identityErr)
	}
	updatedOriginal := identityFixtureManifest(t, "2.0", "updated store extension", nil)
	updatedCRX := crx3TestPackage(t, crx3TestHeader(crx3TestRawID(declaredKey), wrongKey, declaredKey), updatedOriginal)
	updated, err := m.InstallExtensionPackageBytes(storeID, BuildChromeWebStoreURL(storeID), updatedCRX, nil)
	if err != nil {
		t.Fatalf("authentic legacy store record should upgrade in place: %v", err)
	}
	if updated.ExtensionID != legacy.ExtensionID || updated.InstallDir != legacy.InstallDir || updated.Version != "2.0" {
		t.Fatalf("upgrade changed management identity/directory or version: %#v", updated)
	}
	if updated.Enabled || !updated.DefaultInstall {
		t.Fatalf("upgrade changed management settings: enabled=%v default=%v", updated.Enabled, updated.DefaultInstall)
	}
	settings, err := m.ExtensionDAO.GetProfileSettings("legacy-key-profile")
	if err != nil || !settings.Configured || len(settings.ExtensionIDs) != 1 || settings.ExtensionIDs[0] != legacy.ExtensionID {
		t.Fatalf("upgrade changed profile binding: %#v, %v", settings, err)
	}
	stored, err := m.ExtensionDAO.Get(legacy.ExtensionID)
	if err != nil || stored.ExtensionID != legacy.ExtensionID {
		t.Fatalf("management row was not preserved: %#v, %v", stored, err)
	}
	key, ok := readManifestKey(t, filepath.Join(updated.InstallDir, "manifest.json"))
	if !ok || key != extensionManifestKey(declaredKey) {
		t.Fatalf("upgraded manifest key = %q, want declared proof key", key)
	}
	if strings.TrimSpace(stored.ManifestJSON) == "" {
		t.Fatal("upgraded management row lost its manifest")
	}
}

func TestLegacyCRX3WrongFirstProofKeyRejectsUntrustedShapes(t *testing.T) {
	wrongKey := []byte("legacy-first-proof-key")
	declaredKey := []byte("declared-second-proof-key")
	storeID := extensionIDFromPublicKey(declaredKey)
	original := identityFixtureManifest(t, "1.0", "legacy store extension", nil)
	header := crx3TestPackage(t, crx3TestHeader(crx3TestRawID(declaredKey), wrongKey, declaredKey), original)
	crxHeader, err := readStoredCRXHeader(bytes.NewReader(header), int64(len(header)))
	if err != nil {
		t.Fatal(err)
	}
	missingProofPackage := crx3TestPackage(t, crx3TestHeader(crx3TestRawID(declaredKey), wrongKey, []byte("unrelated proof")), original)
	missingProofHeader, err := readStoredCRXHeader(bytes.NewReader(missingProofPackage), int64(len(missingProofPackage)))
	if err != nil {
		t.Fatal(err)
	}
	wrongKeyManifest, err := manifestWithExtensionKey(original, extensionManifestKey(wrongKey))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		recorded  []byte
		installed []byte
		archived  []byte
		header    []byte
		storeID   string
		packageID string
	}{
		{name: "exact historical augmentation", recorded: wrongKeyManifest, archived: original, header: crxHeader, storeID: storeID, packageID: storeID},
		{name: "arbitrary wrong key", recorded: mustManifestKey(t, original, []byte("not-a-proof-key")), archived: original, header: crxHeader, storeID: storeID, packageID: storeID},
		{name: "modified manifest fields", recorded: identityFixtureManifest(t, "1.0", "changed description", wrongKey), archived: original, header: crxHeader, storeID: storeID, packageID: storeID},
		{name: "store ID mismatch", recorded: wrongKeyManifest, archived: original, header: crxHeader, storeID: extensionIDFromPublicKey([]byte("different store")), packageID: storeID},
		{name: "conflicting original key", recorded: wrongKeyManifest, archived: identityFixtureManifest(t, "1.0", "legacy store extension", declaredKey), header: crxHeader, storeID: storeID, packageID: storeID},
		{name: "missing matching proof", recorded: wrongKeyManifest, archived: original, header: missingProofHeader, storeID: storeID, packageID: storeID},
		{name: "missing installed manifest", recorded: wrongKeyManifest, archived: original, header: crxHeader, storeID: storeID, packageID: storeID},
		{name: "generated keyed archive", recorded: wrongKeyManifest, archived: wrongKeyManifest, header: crxHeader, storeID: storeID, packageID: storeID},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			installed := tc.installed
			if installed == nil && tc.name != "missing installed manifest" {
				installed = tc.recorded
			}
			got := legacyCRX3WrongFirstProofKeyAugmentation(tc.recorded, installed, tc.archived, tc.header, tc.storeID, tc.packageID)
			if got != (tc.name == "exact historical augmentation") {
				t.Fatalf("legacy augmentation accepted = %v", got)
			}
		})
	}
}

// Retained-cache verification must consider every staged manifest, even when the
// managed installation authenticates the historical first-proof augmentation.
func TestLegacyCRX3RetainedCacheStagedManifests(t *testing.T) {
	wrongKey := []byte("legacy-first-proof-key")
	declaredKey := []byte("declared-second-proof-key")
	id := extensionIDFromPublicKey(declaredKey)
	original := identityFixtureManifest(t, "1.0", "legacy store extension", nil)
	historical := mustManifestKey(t, original, wrongKey)
	conflictingFields := mustManifestKey(t, identityFixtureManifest(t, "1.0", "modified staged description", nil), wrongKey)
	conflictingKey := mustManifestKey(t, original, []byte("unrelated-staged-key"))
	crx := crx3TestPackage(t, crx3TestHeader(crx3TestRawID(declaredKey), wrongKey, declaredKey), original)

	writeManifestRoot := func(t *testing.T, manifest []byte) string {
		t.Helper()
		root := t.TempDir()
		dir := filepath.Join(root, id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal("cannot create fixture manifest directory")
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o644); err != nil {
			t.Fatal("cannot write fixture manifest")
		}
		return root
	}
	managedRoot := writeManifestRoot(t, historical)
	packagePath := filepath.Join(managedRoot, "packages", id+".crx")
	if err := os.MkdirAll(filepath.Dir(packagePath), 0o755); err != nil {
		t.Fatal("cannot create fixture package directory")
	}
	if err := os.WriteFile(packagePath, crx, 0o644); err != nil {
		t.Fatal("cannot write fixture package")
	}
	legacy := Extension{
		ExtensionID:  id,
		ManifestJSON: string(historical),
		SourceURL:    BuildChromeWebStoreURL(id),
		PackagePath:  packagePath,
		PackageHash:  extensionPackageHash(crx),
	}
	for _, tc := range []struct {
		name         string
		manifests    [][]byte
		wantVerified bool
	}{
		{name: "exact-historical", manifests: [][]byte{historical}, wantVerified: true},
		{name: "original", manifests: [][]byte{original}, wantVerified: true},
		{name: "multiple-valid", manifests: [][]byte{historical, original}, wantVerified: true},
		{name: "conflicting-fields", manifests: [][]byte{conflictingFields}},
		{name: "conflicting-key", manifests: [][]byte{conflictingKey}},
		{name: "later-root-conflicting-fields", manifests: [][]byte{historical, conflictingFields}},
		{name: "later-root-conflicting-key", manifests: [][]byte{original, conflictingKey}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stagedRoots []string
			for _, manifest := range tc.manifests {
				stagedRoots = append(stagedRoots, writeManifestRoot(t, manifest))
			}
			verified, err := VerifyRetainedExtensionCache(legacy, managedRoot, stagedRoots...)
			if tc.wantVerified {
				if !verified || err != nil {
					t.Fatalf("authentic staged manifest rejected: verified=%v, err=%v", verified, err)
				}
			} else if verified || err == nil {
				t.Fatalf("conflicting staged manifest accepted: verified=%v, err=%v", verified, err)
			}
		})
	}
}

func mustManifestKey(t *testing.T, original, key []byte) []byte {
	t.Helper()
	manifest, err := manifestWithExtensionKey(original, extensionManifestKey(key))
	if err != nil || manifest == nil {
		t.Fatalf("manifest key fixture generation failed: %v", err)
	}
	return manifest
}
