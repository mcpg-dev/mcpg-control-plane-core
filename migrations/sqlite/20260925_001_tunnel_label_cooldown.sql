-- When the org's name cap released a public tunnel's host label. The label
-- stays on the row, bound to the org by the global unique index, for seven
-- days: a client still configured with the address reaches nothing rather
-- than whoever registers the name next. The org may bind it again meanwhile;
-- once the cool-down ends the label is cleared and anyone may register it.
ALTER TABLE tunnels ADD COLUMN hostname_released_at TEXT;
