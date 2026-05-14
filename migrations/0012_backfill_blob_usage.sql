WITH `record_blob_ref` AS (
	SELECT
		`record`.`did` AS `did`,
		`record`.`uri` AS `record_uri`,
		`link_node`.`value` AS `cid`,
		`mime_node`.`value` AS `mime`,
		`size_node`.`value` AS `size`
	FROM `record`
	INNER JOIN json_tree(CASE WHEN json_valid(`record`.`json`) THEN `record`.`json` ELSE '{}' END) AS `type_node`
		ON `type_node`.`key` = '$type'
		AND `type_node`.`value` = 'blob'
	INNER JOIN json_tree(CASE WHEN json_valid(`record`.`json`) THEN `record`.`json` ELSE '{}' END) AS `link_node`
		ON `link_node`.`path` = `type_node`.`path` || '.ref'
		AND `link_node`.`key` IN ('$link', '/')
	INNER JOIN json_tree(CASE WHEN json_valid(`record`.`json`) THEN `record`.`json` ELSE '{}' END) AS `mime_node`
		ON `mime_node`.`path` = `type_node`.`path`
		AND `mime_node`.`key` = 'mimeType'
	INNER JOIN json_tree(CASE WHEN json_valid(`record`.`json`) THEN `record`.`json` ELSE '{}' END) AS `size_node`
		ON `size_node`.`path` = `type_node`.`path`
		AND `size_node`.`key` = 'size'
	WHERE `link_node`.`type` = 'text'
		AND `mime_node`.`type` = 'text'
		AND `size_node`.`type` = 'integer'
)
INSERT OR IGNORE INTO `blob_usage` ("did", "record_uri", "key", "cid", "repo_rev")
SELECT
	`record_blob_ref`.`did`,
	`record_blob_ref`.`record_uri`,
	`blob`.`key`,
	`blob`.`cid`,
	COALESCE(`repo_root`.`rev`, '')
FROM `record_blob_ref`
INNER JOIN `blob`
	ON `blob`.`did` = `record_blob_ref`.`did`
	AND `blob`.`cid` = `record_blob_ref`.`cid`
	AND `blob`.`mime` = `record_blob_ref`.`mime`
	AND `blob`.`size` = `record_blob_ref`.`size`
LEFT JOIN `repo_root`
	ON `repo_root`.`did` = `record_blob_ref`.`did`;
