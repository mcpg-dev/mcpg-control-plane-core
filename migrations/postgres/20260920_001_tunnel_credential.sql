-- The service token (`mcpgst_`) a tunnel was registered with. Every heartbeat
-- checks it, so revoking the token, or its expiry, closes the tunnel instead of
-- leaving it open until the gateway next reconnects.
--
-- No foreign key: a token row that is gone must read as revoked, which a
-- cascade or SET NULL would hide. NULL for a row registered before the column
-- existed; its next register records the token.
ALTER TABLE tunnels ADD COLUMN credential_id UUID;
