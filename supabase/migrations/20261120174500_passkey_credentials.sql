begin;

create table if not exists public.passkeys (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null,
    credential_id text not null unique,
    public_key text not null,
    counter bigint not null default 0 check (counter >= 0),
    transports text[] not null default '{}'::text[],
    created_at timestamptz not null default now()
);

alter table public.passkeys enable row level security;
revoke all on table public.passkeys from public, anon, authenticated;
grant select, insert, update, delete on table public.passkeys to service_role;

commit;
