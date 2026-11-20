begin;

create table if not exists public.users (
    id uuid primary key default gen_random_uuid(),
    oauth_provider text not null check (oauth_provider in ('google', 'microsoft')),
    oauth_subject_hash text not null unique,
    created_at timestamptz not null default now()
);

alter table public.passkeys
    add column if not exists created_at timestamptz not null default now();

do $$
begin
    if not exists (
        select 1
        from pg_constraint
        where conname = 'passkeys_user_id_fkey'
          and conrelid = 'public.passkeys'::regclass
    ) then
        alter table public.passkeys
            add constraint passkeys_user_id_fkey
            foreign key (user_id)
            references public.users(id)
            on delete cascade
            not valid;
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1
        from public.passkeys passkey
        left join public.users account on account.id = passkey.user_id
        where account.id is null
    ) then
        alter table public.passkeys
            validate constraint passkeys_user_id_fkey;
    end if;
end
$$;

create table if not exists public.wallet_credentials (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null unique references public.users(id) on delete cascade,
    verified boolean not null default false,
    is_adult boolean not null default false,
    document_type text,
    issuing_country text,
    verified_at timestamptz,
    expires_at timestamptz
);

alter table public.users enable row level security;
alter table public.passkeys enable row level security;
alter table public.wallet_credentials enable row level security;

revoke all on table public.users, public.passkeys, public.wallet_credentials
    from public, anon, authenticated;
grant select, insert, update, delete on table public.users,
    public.passkeys, public.wallet_credentials to service_role;

revoke insert, update, delete on table public.verifications from public, anon, authenticated;
grant insert on table public.verifications to service_role;

commit;
