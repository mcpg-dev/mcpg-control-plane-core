-- A public tunnel's `hostname` holds its host label: the lowercased tunnel
-- name, which is the first DNS label the relay routes on. See the postgres
-- mirror for the full rationale. Public rows with no label get one here; where
-- several orgs registered one label, the oldest registration keeps it.
UPDATE tunnels
   SET hostname = lower(name)
 WHERE exposure = 'public'
   AND hostname IS NULL
   AND length(name) BETWEEN 1 AND 63
   AND lower(name) NOT GLOB '*[^a-z0-9-]*'
   AND name NOT GLOB '-*'
   AND name NOT GLOB '*-'
   AND NOT EXISTS (SELECT 1 FROM tunnels h WHERE h.hostname = lower(tunnels.name))
   AND NOT EXISTS (
       SELECT 1 FROM tunnels o
        WHERE o.exposure = 'public'
          AND o.hostname IS NULL
          AND lower(o.name) = lower(tunnels.name)
          AND (o.created_at, o.org_id, o.name) < (tunnels.created_at, tunnels.org_id, tunnels.name)
   );
