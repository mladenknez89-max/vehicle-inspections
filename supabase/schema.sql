-- Vehicle Inspection – Supabase šema
-- Pokreni jednom: Supabase → SQL Editor → New query → nalepi ceo fajl → Run.

-- ── Vozači ──────────────────────────────────────────────
create table if not exists public.drivers (
  id          bigint generated always as identity primary key,
  full_name   text not null check (length(trim(full_name)) between 2 and 100),
  driver_id   text not null check (driver_id ~ '^[0-9]{4}$'),   -- poslednje 4 cifre telefona
  active      boolean not null default true,                    -- neaktivan vozač ne može da šalje izveštaje
  created_at  timestamptz not null default now()
);
create index if not exists drivers_driver_id_idx on public.drivers (driver_id);

-- ── Izveštaji ───────────────────────────────────────────
create table if not exists public.reports (
  id              bigint generated always as identity primary key,
  created_at      timestamptz not null default now(),
  report_date     date not null,                 -- samo datum (vremenska zona iz APP_TIMEZONE)
  driver_name     text not null,
  driver_id       text not null,
  truck           text not null,
  trailer         text not null,
  truck_photos    text[] not null default '{}',  -- adrese slika (R2 ili stari Cloudinary)
  trailer_photos  text[] not null default '{}',
  notes           text not null default '',
  admin_comment   text not null default ''
);
create index if not exists reports_date_idx on public.reports (report_date desc, id desc);

-- ── Zaključavanje ───────────────────────────────────────
-- RLS uključen, bez ijedne "policy": niko spolja ne može da čita ni piše.
-- Pristupa samo server (Netlify funkcija) sa secret / service_role ključem.
alter table public.drivers enable row level security;
alter table public.reports enable row level security;
revoke all on public.drivers, public.reports from anon, authenticated;
