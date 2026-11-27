package backend

import (
	"database/sql"
	"errors"
	"fmt"

	"ant-chrome/backend/internal/browser"
)

var errExtensionRestoreIdentityConflict = errors.New("插件身份冲突")

func checkExtensionRestoreIdentity(source, target browser.Extension, sourceRoot, targetRoot string) error {
	sourceID, err := browser.ExtensionRestoreIdentity(source, sourceRoot, true)
	if err != nil {
		return fmt.Errorf("%w (%s)：无法验证备份插件身份: %v", errExtensionRestoreIdentityConflict, source.ExtensionID, err)
	}
	targetID, err := browser.ExtensionRestoreIdentity(target, targetRoot, false)
	if err != nil {
		return fmt.Errorf("%w (%s)：无法验证目标插件身份: %v", errExtensionRestoreIdentityConflict, target.ExtensionID, err)
	}
	if sourceID == "" || targetID == "" || sourceID != targetID {
		return fmt.Errorf("%w (%s)：同一管理 ID 的备份和目标插件身份不同或无法证实相同", errExtensionRestoreIdentityConflict, source.ExtensionID)
	}
	return nil
}

func queryExtensionRestoreRecords(tx *sql.Tx, source bool) (map[string]browser.Extension, error) {
	relation, packagePath, packageHash := "main.browser_extensions", "COALESCE(s.package_path,'')", "COALESCE(s.package_hash,'')"
	if source {
		relation = "src.browser_extensions"
		var err error
		packagePath, err = backupSourceColumnExpression(tx, "browser_extensions", "s", "package_path", "''")
		if err != nil {
			return nil, err
		}
		packageHash, err = backupSourceColumnExpression(tx, "browser_extensions", "s", "package_hash", "''")
		if err != nil {
			return nil, err
		}
	}
	rows, err := tx.Query(fmt.Sprintf(
		"SELECT extension_id, COALESCE(manifest_json,''), COALESCE(source_url,''), COALESCE(install_dir,''), %s, %s FROM %s s ORDER BY extension_id",
		packagePath, packageHash, relation))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make(map[string]browser.Extension)
	for rows.Next() {
		var record browser.Extension
		if err := rows.Scan(&record.ExtensionID, &record.ManifestJSON, &record.SourceURL, &record.InstallDir, &record.PackagePath, &record.PackageHash); err != nil {
			return nil, err
		}
		if key := backupImportIDKey(record.ExtensionID); key != "" {
			if _, exists := records[key]; exists {
				return nil, fmt.Errorf("%w (%s)：存在重复管理 ID", errExtensionRestoreIdentityConflict, record.ExtensionID)
			}
			records[key] = record
		}
	}
	return records, rows.Err()
}
