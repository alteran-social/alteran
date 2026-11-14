console.error(
  "Local D1 reset is disabled because Wrangler's default D1 state can be shared by multiple environments and databases. Back up the local state and use a database-specific reset procedure.",
);
Deno.exit(1);
