-- 008_platform_target_expansion.sql
-- Widens platform + target_type CHECK constraints to support more
-- program platforms and more specific asset types. Purely additive -
-- no existing row's value changes, old values stay valid.

ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_platform_check;
ALTER TABLE projects ADD CONSTRAINT projects_platform_check
    CHECK (platform IN ('bugcrowd', 'hackerone', 'intigriti', 'yeswehack', 'openbugbounty', 'private'));

ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS scope_targets_target_type_check;
ALTER TABLE scope_targets ADD CONSTRAINT scope_targets_target_type_check
    CHECK (target_type IN (
        'website', 'api', 'mobile', 'hardware', 'unknown',
        'domain', 'wildcard', 'url', 'hardware_iot', 'other',
        'android_play_store', 'ios_app_store', 'smart_contract',
        'source_code', 'executable'
    ));
