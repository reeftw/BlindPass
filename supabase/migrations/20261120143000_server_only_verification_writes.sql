begin;

alter table public.verifications
    add column if not exists verified boolean not null default false,
    add column if not exists document_type text,
    add column if not exists issuing_country text,
    add column if not exists is_adult boolean,
    add column if not exists session_token_hash text,
    add column if not exists verified_at timestamptz;

update public.verifications
set verified = true,
    is_adult = is_over_18
where is_over_18 is not null;

create unique index if not exists verifications_session_token_hash_unique
    on public.verifications (session_token_hash)
    where session_token_hash is not null;

revoke insert, update, delete on table public.verifications from public, anon, authenticated;
grant insert on table public.verifications to service_role;

commit;
