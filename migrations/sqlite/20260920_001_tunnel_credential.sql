-- The service token (`mcpgst_`) a tunnel was registered with. See the postgres
-- mirror for the rationale.
ALTER TABLE tunnels ADD COLUMN credential_id TEXT;
