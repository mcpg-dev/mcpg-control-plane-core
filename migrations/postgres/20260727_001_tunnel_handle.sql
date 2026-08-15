-- Opaque per-registration handle for the relay's heartbeat/deregister calls.
--
-- Those calls identified the tunnel by a body-supplied `org_id` behind a single
-- shared relay token, so any holder of that token — or any caller at all when
-- the CP runs without auth — could attribute tunnel bytes to an arbitrary org.
-- RLS cannot help: the scope is opened WITH the supplied org, so the row policy
-- passes by construction.
--
-- The handle is minted at register, returned once, and resolves the org on
-- every later call. NULL for rows registered before this column existed; those
-- keep the previous behaviour until the relay is switched over.
ALTER TABLE tunnels ADD COLUMN handle TEXT;

CREATE UNIQUE INDEX tunnels_handle_idx ON tunnels (handle) WHERE handle IS NOT NULL;
