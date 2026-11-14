CREATE INDEX `oauth_replay_expiry` ON `secret` (
  (CASE WHEN json_valid(`value`) THEN CASE
    WHEN `key` GLOB 'oauth:dpop:jti:*'
      AND json_type(`value`, '$.exp') IN ('integer', 'real')
      AND json_type(`value`, '$.iat') IN ('integer', 'real')
      THEN MAX(CAST(json_extract(`value`, '$.exp') AS REAL), CAST(json_extract(`value`, '$.iat') AS REAL) + 300)
    WHEN `key` GLOB 'oauth:client-assertion:jti:*'
      AND json_type(`value`, '$.exp') IN ('integer', 'real')
      THEN CAST(json_extract(`value`, '$.exp') AS REAL)
    ELSE NULL END ELSE NULL END), `key`
) WHERE `key` GLOB 'oauth:dpop:jti:*' OR `key` GLOB 'oauth:client-assertion:jti:*';
