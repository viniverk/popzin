-- =====================================================================
-- PopZin — configuração do banco no Supabase (rodar UMA vez)
-- Supabase → SQL Editor → New query → cole tudo → troque o e-mail
-- na última seção → Run
-- =====================================================================

-- 1) Tabelas ----------------------------------------------------------
create table if not exists public.produtos (
  id         bigint primary key,
  dados      jsonb  not null,
  atualizado timestamptz not null default now()
);

create table if not exists public.loja (
  id         int primary key default 1 check (id = 1),   -- uma linha só
  dados      jsonb not null,
  atualizado timestamptz not null default now()
);

-- quem pode editar (e-mails dos administradores)
create table if not exists public.admins (
  email text primary key
);

-- 2) Função que diz se quem está logado é administrador ----------------
create or replace function public.eh_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.admins
    where lower(email) = lower(coalesce(auth.jwt() ->> 'email', ''))
  );
$$;

-- 3) Segurança: todo mundo lê, só administrador escreve ----------------
alter table public.produtos enable row level security;
alter table public.loja     enable row level security;
alter table public.admins   enable row level security;   -- sem políticas = ninguém acessa pela API

drop policy if exists "produtos: leitura publica"  on public.produtos;
drop policy if exists "produtos: admin escreve"    on public.produtos;
drop policy if exists "loja: leitura publica"      on public.loja;
drop policy if exists "loja: admin escreve"        on public.loja;

create policy "produtos: leitura publica" on public.produtos
  for select using (true);
create policy "produtos: admin escreve" on public.produtos
  for all to authenticated using (public.eh_admin()) with check (public.eh_admin());

create policy "loja: leitura publica" on public.loja
  for select using (true);
create policy "loja: admin escreve" on public.loja
  for all to authenticated using (public.eh_admin()) with check (public.eh_admin());

grant select on public.produtos, public.loja to anon, authenticated;
grant insert, update, delete on public.produtos, public.loja to authenticated;
grant execute on function public.eh_admin() to anon, authenticated;

-- 4) Pasta pública das artes (fotos) -------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('artes', 'artes', true, 5242880, array['image/webp','image/jpeg','image/png'])
on conflict (id) do update set public = true;

drop policy if exists "artes: admin le"      on storage.objects;
drop policy if exists "artes: admin envia"   on storage.objects;
drop policy if exists "artes: admin altera"  on storage.objects;
drop policy if exists "artes: admin apaga"   on storage.objects;

create policy "artes: admin le" on storage.objects
  for select to authenticated using (bucket_id = 'artes' and public.eh_admin());
create policy "artes: admin envia" on storage.objects
  for insert to authenticated with check (bucket_id = 'artes' and public.eh_admin());
create policy "artes: admin altera" on storage.objects
  for update to authenticated using (bucket_id = 'artes' and public.eh_admin());
create policy "artes: admin apaga" on storage.objects
  for delete to authenticated using (bucket_id = 'artes' and public.eh_admin());

-- 5) SEU E-MAIL de administrador ------------------------------------------
--    Troque pelo e-mail que você vai usar para entrar no painel
--    (o mesmo do usuário criado em Authentication → Users).
insert into public.admins (email) values ('SEU-EMAIL-AQUI@exemplo.com')
on conflict do nothing;
