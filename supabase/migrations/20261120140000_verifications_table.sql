begin;

create table if not exists public.verifications (
    id uuid primary key default gen_random_uuid(),
    verified boolean not null default false,
    is_over_18 boolean,
    document_type text,
    issuing_country text,
    is_adult boolean,
    session_token_hash text,
    verified_at timestamptz
);

alter table public.verifications enable row level security;

revoke all on table public.verifications from public, anon, authenticated;
grant all on table public.verifications to service_role;

commit;
