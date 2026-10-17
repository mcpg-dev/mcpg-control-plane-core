-- A public tunnel's `hostname` holds its host label: the lowercased tunnel
-- name, which is the first DNS label the relay routes on. The global unique
-- index `tunnels_hostname_uq` then binds each public address to one org, and
-- the label stays on the row after the tunnel closes.
--
-- Public rows with no label get one here, so every public address is bound
-- from the moment this runs. Where several orgs registered one label, the
-- oldest registration keeps it; the others are refused at their next
-- register. A name that cannot be a DNS label is left unbound — the control
-- plane refuses it as public anyway.
--
-- FORCEd RLS hides every row from the owner role outside an org scope, so the
-- backfill lifts FORCE for its one statement and restores it.
ALTER TABLE tunnels NO FORCE ROW LEVEL SECURITY;

UPDATE tunnels t
   SET hostname = lower(t.name)
 WHERE t.exposure = 'public'
   AND t.hostname IS NULL
   AND lower(t.name) ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
   AND NOT EXISTS (SELECT 1 FROM tunnels h WHERE h.hostname = lower(t.name))
   AND NOT EXISTS (
       SELECT 1 FROM tunnels o
        WHERE o.exposure = 'public'
          AND o.hostname IS NULL
          AND lower(o.name) = lower(t.name)
          AND (o.created_at, o.org_id::text, o.name) < (t.created_at, t.org_id::text, t.name)
   );

ALTER TABLE tunnels FORCE ROW LEVEL SECURITY;
