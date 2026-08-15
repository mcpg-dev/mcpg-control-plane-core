-- Bind a bootstrap token to the instance_uid it is allowed to enroll.
-- NULL = unbound (self-host: any uid may consume it, legacy behaviour).
-- When set (cloud: the CP minted the instance and pre-created its row), the
-- enrolling gateway MUST present this exact uid or consume() is rejected —
-- anti-spoofing so one tenant's token can't claim another instance's identity.
ALTER TABLE bootstrap_tokens ADD COLUMN expected_instance_uid TEXT NULL;
