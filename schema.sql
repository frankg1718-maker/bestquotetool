-- ============================================================================
-- BestQuoteTool — Supabase schema (run ONCE in the Supabase SQL editor)
-- ----------------------------------------------------------------------------
-- Tables:
--   public.profiles   one row per account: subscription flags + counters
--   public.documents  Cloud Saving documents (opt-in subscribers only)
--   public.office_codes    one row per account: the OFFICE CODE, stored HASHED
--   public.office_sessions office (work-only) sign-ins on an account
--   public.office_pairings one-time QR pairing tokens for office sign-in
--
-- OFFICE CODE DESIGN (locked spec §2): the code itself is NEVER stored and
-- never leaves the owner's devices in plain text — only its SHA-256 hash is
-- kept here (office_codes.code_hash). Verification happens through the two
-- security-definer functions at the bottom of this file, so the hash is
-- never shipped to a client that doesn't already own the account. Those
-- functions are a verification oracle by nature: before go-live, put
-- rate limiting in front of them (Supabase edge function / platform
-- limits). The client also locks the office sign-in form after 5 wrong
-- tries (15 minutes), but client lockout is a courtesy, not the wall.
--
-- SECURITY MODEL:
--   * Row-level security is ON for both tables: a signed-in user can only
--     ever see or touch their OWN rows.
--   * The paid flags (profiles.subscribed, profiles.cloud_saving,
--     profiles.founding_lock and its companion columns) are
--     writable ONLY by the service role — i.e. the Stripe webhook / an
--     admin script. The browser client cannot set them: the column-level
--     GRANT below gives "authenticated" UPDATE rights on tests_used and
--     cloud_enabled ONLY. Client attempts to write the flags are rejected
--     by Postgres itself.
--   * profiles.stripe_customer_id links the account to Stripe; the webhook
--     matches on it (or on email) when flipping the flags.
--   * The client (anon key + the user's own JWT) READS its own flags only.
-- ============================================================================

-- ---------- profiles ---------------------------------------------------------
create table if not exists public.profiles (
  id                uuid primary key references auth.users (id) on delete cascade,
  email             text,
  subscribed        boolean not null default false,  -- PAID FLAG: service role only
  cloud_saving      boolean not null default false,  -- PAID FLAG: service role only
  cloud_enabled     boolean not null default true,   -- user's own on/off switch for the feature
  tests_used        integer not null default 0,      -- free generated-estimate tests consumed
  stripe_customer_id text,                           -- set by webhook / admin (service role)
  founding_lock     boolean not null default false,  -- PAID FLAG: service role only (see below)
  locked_base_price_cents integer,                   -- 1900 for founding accounts; null otherwise
  subscription_started_at timestamptz,               -- when the paid subscription first became active
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);

-- Founding price lock (Franklin's ruling, Nov 17, 2026 — Terms Clause 6):
-- subscriptions started during the first 30 days after launch lock the
-- base price at $19/mo for as long as the subscription stays active
-- without interruption. The founding window is NOT stored per user: it
-- derives from the launch date (LAUNCH_DATE in js/bqt-config.js) + 30
-- days. The stamp happens service-role side, at the moment a
-- subscription first becomes active (the Stripe webhook / admin script —
-- the same place that flips `subscribed`):
--   * always set subscription_started_at on first activation;
--   * if that start time falls within 30 days of the launch date, also
--     set founding_lock = true and locked_base_price_cents = 1900.
-- When a subscription ends (cancel / deletion), the webhook clears
-- founding_lock: cancel ends the lock, and a later re-subscribe takes
-- the then-current price (Terms Clause 6). The three founding columns
-- are deliberately NOT in the authenticated UPDATE grant below — like
-- `subscribed`, they are service-role-only: the app can KNOW who is
-- founding, but a client can never MAKE itself founding.
-- (The alter statements cover a database where profiles already exists
-- from an earlier run of this file; on a fresh run they are no-ops.)
alter table public.profiles add column if not exists founding_lock boolean not null default false;
alter table public.profiles add column if not exists locked_base_price_cents integer;
alter table public.profiles add column if not exists subscription_started_at timestamptz;

alter table public.profiles enable row level security;

drop policy if exists "profiles: read own"   on public.profiles;
drop policy if exists "profiles: insert own" on public.profiles;
drop policy if exists "profiles: update own" on public.profiles;

create policy "profiles: read own"
  on public.profiles for select
  to authenticated
  using (auth.uid() = id);

create policy "profiles: insert own"
  on public.profiles for insert
  to authenticated
  with check (auth.uid() = id);

create policy "profiles: update own"
  on public.profiles for update
  to authenticated
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- Column-level write protection: even with the UPDATE policy above, the
-- browser role may only write these two columns. subscribed, cloud_saving,
-- founding_lock, locked_base_price_cents, subscription_started_at,
-- stripe_customer_id, id and email stay service-role-only.
revoke update on table public.profiles from authenticated, anon;
grant  update (tests_used, cloud_enabled) on table public.profiles to authenticated;
revoke insert on table public.profiles from anon;
grant  select, insert on table public.profiles to authenticated;

-- Create the profile row automatically when an account is created.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email)
  values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Keep updated_at honest.
create or replace function public.touch_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_touch on public.profiles;
create trigger profiles_touch
  before update on public.profiles
  for each row execute function public.touch_updated_at();

-- ---------- documents (Cloud Saving) -----------------------------------------
create table if not exists public.documents (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users (id) on delete cascade,
  tool       text not null check (tool in ('painting', 'carpentry', 'tasks')),
  kind       text not null,  -- quote | invoice | receipt | estimate
  title      text,
  doc        jsonb not null, -- the generated document snapshot (tool state JSON)
  created_at timestamptz not null default now()
);

-- Job hygiene (locked spec §2): every document carries a version number and
-- an updated-at stamp, and deleting is a SOFT delete (deleted_at) so the
-- Trash view can restore it. Delete-forever is the only hard delete.
alter table public.documents add column if not exists deleted_at timestamptz;
alter table public.documents add column if not exists version    integer not null default 1;
alter table public.documents add column if not exists updated_at timestamptz not null default now();

create index if not exists documents_user_created_idx
  on public.documents (user_id, created_at desc);

drop trigger if exists documents_touch on public.documents;
create trigger documents_touch
  before update on public.documents
  for each row execute function public.touch_updated_at();

alter table public.documents enable row level security;

drop policy if exists "documents: read own"   on public.documents;
drop policy if exists "documents: insert own" on public.documents;
drop policy if exists "documents: update own" on public.documents;
drop policy if exists "documents: delete own" on public.documents;

create policy "documents: read own"
  on public.documents for select
  to authenticated
  using (auth.uid() = user_id);

create policy "documents: insert own"
  on public.documents for insert
  to authenticated
  with check (auth.uid() = user_id);

create policy "documents: update own"
  on public.documents for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

create policy "documents: delete own"
  on public.documents for delete
  to authenticated
  using (auth.uid() = user_id);

grant select, insert, update, delete on table public.documents to authenticated;

-- ---------- office codes (locked spec §2) ------------------------------------
-- One standing code per account, generated by the ACCOUNT HOLDER (never by
-- us). Only the SHA-256 hash is stored. Reset = replace the hash; the old
-- code dies instantly because its hash no longer matches anything.
create table if not exists public.office_codes (
  user_id    uuid primary key references auth.users (id) on delete cascade,
  code_hash  text not null,  -- SHA-256 hex of the office code — never the code
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.office_codes enable row level security;

drop policy if exists "office_codes: read own"   on public.office_codes;
drop policy if exists "office_codes: insert own" on public.office_codes;
drop policy if exists "office_codes: update own" on public.office_codes;

create policy "office_codes: read own"
  on public.office_codes for select
  to authenticated
  using (auth.uid() = user_id);

create policy "office_codes: insert own"
  on public.office_codes for insert
  to authenticated
  with check (auth.uid() = user_id);

create policy "office_codes: update own"
  on public.office_codes for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

grant select, insert, update on table public.office_codes to authenticated;

drop trigger if exists office_codes_touch on public.office_codes;
create trigger office_codes_touch
  before update on public.office_codes
  for each row execute function public.touch_updated_at();

-- ---------- office sessions ---------------------------------------------------
-- One row per office (work-only) sign-in. The owner sees these in
-- Account → Office Access and can revoke any of them (revoked_at).
create table if not exists public.office_sessions (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references auth.users (id) on delete cascade,
  label       text,  -- e.g. "Office session — Chrome on Windows"
  created_at  timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  revoked_at  timestamptz
);

create index if not exists office_sessions_user_idx
  on public.office_sessions (user_id, created_at desc);

alter table public.office_sessions enable row level security;

drop policy if exists "office_sessions: read own"   on public.office_sessions;
drop policy if exists "office_sessions: insert own" on public.office_sessions;
drop policy if exists "office_sessions: update own" on public.office_sessions;

create policy "office_sessions: read own"
  on public.office_sessions for select
  to authenticated
  using (auth.uid() = user_id);

create policy "office_sessions: insert own"
  on public.office_sessions for insert
  to authenticated
  with check (auth.uid() = user_id);

create policy "office_sessions: update own"
  on public.office_sessions for update
  to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

grant select, insert, update on table public.office_sessions to authenticated;

-- ---------- office pairings (QR sign-in) --------------------------------------
-- One-time tokens behind the "Show QR" action in Office Access. Only the
-- SHA-256 hash of the token is stored; the token itself lives in the QR the
-- owner shows and in the scanning device's URL, once, for 10 minutes.
create table if not exists public.office_pairings (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users (id) on delete cascade,
  token_hash text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_at    timestamptz
);

create index if not exists office_pairings_hash_idx
  on public.office_pairings (token_hash);

alter table public.office_pairings enable row level security;

drop policy if exists "office_pairings: insert own" on public.office_pairings;
drop policy if exists "office_pairings: read own"   on public.office_pairings;

create policy "office_pairings: insert own"
  on public.office_pairings for insert
  to authenticated
  with check (auth.uid() = user_id);

create policy "office_pairings: read own"
  on public.office_pairings for select
  to authenticated
  using (auth.uid() = user_id);

grant select, insert on table public.office_pairings to authenticated;

-- ---------- office verification functions (security definer) ------------------
-- These two functions are the ONLY way an office code / pairing token gets
-- checked. They run as the definer so an unauthenticated scanning device
-- never reads the tables directly. ADD RATE LIMITING BEFORE GO-LIVE.
create extension if not exists pgcrypto;

-- Redeem a one-time QR pairing token. Returns the account email on success
-- (and records the office session), or an empty set when the token is
-- unknown, expired, or already used.
create or replace function public.redeem_office_pairing(p_token text, p_label text default null)
returns table (account_email text, session_id uuid)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_hash text := encode(digest(p_token, 'sha256'), 'hex');
  v_row  public.office_pairings%rowtype;
  v_email text;
  v_sid uuid;
begin
  select * into v_row from public.office_pairings
    where token_hash = v_hash and used_at is null and expires_at > now()
    limit 1;
  if not found then return; end if;
  update public.office_pairings set used_at = now() where id = v_row.id;
  select email into v_email from public.profiles where id = v_row.user_id;
  insert into public.office_sessions (user_id, label)
    values (v_row.user_id, coalesce(p_label, 'Office session (QR)'))
    returning id into v_sid;
  account_email := v_email; session_id := v_sid; return next;
end;
$$;

-- Look up an office code by its hash (the client hashes before sending, so
-- the plain code never travels). Returns the account email + a fresh office
-- session id on success, or an empty set when no account matches.
create or replace function public.office_signin_lookup(p_code_hash text, p_label text default null)
returns table (account_email text, session_id uuid)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid;
  v_email text;
  v_sid uuid;
begin
  select user_id into v_uid from public.office_codes where code_hash = p_code_hash limit 1;
  if v_uid is null then return; end if;
  select email into v_email from public.profiles where id = v_uid;
  insert into public.office_sessions (user_id, label)
    values (v_uid, coalesce(p_label, 'Office session'))
    returning id into v_sid;
  account_email := v_email; session_id := v_sid; return next;
end;
$$;

grant execute on function public.redeem_office_pairing(text, text)  to anon, authenticated;
grant execute on function public.office_signin_lookup(text, text)   to anon, authenticated;

-- ============================================================================
-- STRIPE WEBHOOK (service role) — what flips the flags when someone pays:
--   update public.profiles set subscribed   = true  where stripe_customer_id = '<cus_...>';
--   update public.profiles set cloud_saving = true  where stripe_customer_id = '<cus_...>';
-- (and the matching "= false" on cancellation / subscription deletion.)
-- FOUNDING LOCK (same webhook, on FIRST activation only): stamp
-- subscription_started_at = <subscription start>, and — when that start
-- falls within 30 days of LAUNCH_DATE (js/bqt-config.js) — also set
-- founding_lock = true, locked_base_price_cents = 1900. On cancellation
-- / subscription deletion, set founding_lock = false (cancel ends the
-- lock). Stripe itself needs no change for locked users: a Stripe
-- subscription keeps the price it started on — a future price rise is
-- a NEW price offered to NEW subscribers only.
-- The service-role key bypasses RLS and column grants by design; it must
-- only ever live in the webhook/server environment, never in the website.
-- ============================================================================
