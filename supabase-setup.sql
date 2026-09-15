-- ============================================================
-- منصة السعيد — إعداد قاعدة البيانات (Supabase)
-- الصقه كاملًا في: SQL Editor → New query → Run
-- غيّر بريد الأدمن في السطر التالي قبل التشغيل إن أردت:
-- ============================================================
create or replace function public.admin_email() returns text language sql immutable as $$ select 'admin@al-ltc.com' $$;

-- 1) الجداول
create table if not exists public.profiles (
  id uuid primary key references auth.users on delete cascade,
  email text, name text, phone text,
  role text not null default 'student',
  status text not null default 'pending',     -- pending | active | suspended
  expires timestamptz,
  created_at timestamptz default now()
);
create table if not exists public.progress (
  user_id uuid primary key references auth.users on delete cascade,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz default now()
);
create table if not exists public.site_data (
  id text primary key,
  data jsonb not null,
  updated_at timestamptz default now()
);
create table if not exists public.files (
  id uuid primary key default gen_random_uuid(),
  name text, size bigint, type text, path text not null,
  created_at timestamptz default now()
);

-- 2) هل المستخدم الحالي أدمن؟ (security definer لتجنّب التكرار في RLS)
create or replace function public.is_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin' and status = 'active')
$$;

-- 3) إنشاء الملف الشخصي تلقائيًا عند التسجيل
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, name, phone, role, status)
  values (new.id, new.email,
          coalesce(new.raw_user_meta_data->>'name', ''),
          coalesce(new.raw_user_meta_data->>'phone', ''),
          case when lower(new.email) = lower(public.admin_email()) then 'admin' else 'student' end,
          case when lower(new.email) = lower(public.admin_email()) then 'active' else 'pending' end)
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

-- 4) الصلاحيات (RLS)
alter table public.profiles  enable row level security;
alter table public.progress  enable row level security;
alter table public.site_data enable row level security;
alter table public.files     enable row level security;

drop policy if exists "profiles read"   on public.profiles;
drop policy if exists "profiles admin"  on public.profiles;
create policy "profiles read"  on public.profiles for select using (auth.uid() = id or public.is_admin());
create policy "profiles admin" on public.profiles for all    using (public.is_admin()) with check (public.is_admin());

drop policy if exists "progress own"        on public.progress;
drop policy if exists "progress admin read" on public.progress;
drop policy if exists "progress admin del"  on public.progress;
create policy "progress own"        on public.progress for all    using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "progress admin read" on public.progress for select using (public.is_admin());
create policy "progress admin del"  on public.progress for delete using (public.is_admin());

drop policy if exists "site read"  on public.site_data;
drop policy if exists "site admin" on public.site_data;
create policy "site read"  on public.site_data for select to authenticated using (true);
create policy "site admin" on public.site_data for all    using (public.is_admin()) with check (public.is_admin());

drop policy if exists "files read"  on public.files;
drop policy if exists "files admin" on public.files;
create policy "files read"  on public.files for select to authenticated using (true);
create policy "files admin" on public.files for all    using (public.is_admin()) with check (public.is_admin());

-- 5) مخزن الملفات (PDF وغيرها)
insert into storage.buckets (id, name, public, file_size_limit)
values ('files', 'files', false, 52428800) on conflict (id) do nothing;
drop policy if exists "storage read"  on storage.objects;
drop policy if exists "storage admin" on storage.objects;
create policy "storage read"  on storage.objects for select to authenticated using (bucket_id = 'files');
create policy "storage admin" on storage.objects for all    using (bucket_id = 'files' and public.is_admin()) with check (bucket_id = 'files' and public.is_admin());

-- 6) الأدمن: إن كان بريد الأدمن مسجَّلًا مسبقًا فعّله
update public.profiles set role = 'admin', status = 'active' where lower(email) = lower(public.admin_email());
