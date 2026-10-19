-- =====================================================
-- CityMarket: Step 1 schema (run in Supabase SQL Editor)
-- =====================================================

-- ---------- ENUMS ----------
create type user_role as enum ('customer', 'shopkeeper', 'admin');
create type shop_status as enum ('pending', 'approved', 'suspended', 'rejected');
create type order_status as enum (
  'placed', 'accepted', 'preparing', 'out_for_delivery',
  'delivered', 'cancelled', 'rejected'
);
create type payment_method as enum ('cod', 'online');
create type payment_status as enum ('pending', 'paid', 'failed', 'refunded');

-- ---------- 1. USERS (profiles) ----------
-- Supabase manages credentials in auth.users. This table extends it.
create table public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  full_name   text not null,
  phone       text unique,
  avatar_url  text,
  role        user_role not null default 'customer',
  address     text,
  pincode     text,
  latitude    double precision,
  longitude   double precision,
  is_active   boolean not null default true,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- Auto-create a profile whenever someone signs up.
-- Role is always 'customer' here; admins promote shopkeepers/admins manually.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, full_name, phone)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', 'New User'),
    new.phone
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Helper used by RLS policies
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from profiles where id = auth.uid() and role = 'admin');
$$;

-- ---------- 2. SHOPS ----------
create table public.shops (
  id                uuid primary key default gen_random_uuid(),
  owner_id          uuid not null references public.profiles(id) on delete cascade,
  name              text not null,
  slug              text unique not null,
  description       text,
  category          text,                       -- e.g. grocery, bakery, pharmacy
  logo_url          text,
  banner_url        text,
  phone             text,
  address           text not null,
  pincode           text not null,
  latitude          double precision not null,
  longitude         double precision not null,
  delivery_radius_km numeric(5,2) not null default 5,
  min_order_amount  numeric(10,2) not null default 0,
  delivery_fee      numeric(10,2) not null default 0,
  opening_time      time,
  closing_time      time,
  is_open           boolean not null default true,
  status            shop_status not null default 'pending',
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);
create index shops_pincode_idx on public.shops (pincode);
create index shops_owner_idx   on public.shops (owner_id);
create index shops_status_idx  on public.shops (status);

-- ---------- 3. PRODUCTS ----------
create table public.products (
  id              uuid primary key default gen_random_uuid(),
  shop_id         uuid not null references public.shops(id) on delete cascade,
  name            text not null,
  description     text,
  category        text,
  image_urls      text[] not null default '{}',
  price           numeric(10,2) not null check (price >= 0),
  mrp             numeric(10,2) check (mrp >= 0),   -- strike-through price
  unit            text not null default 'piece',    -- kg, litre, piece, pack
  stock_quantity  integer not null default 0 check (stock_quantity >= 0),
  is_available    boolean not null default true,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);
create index products_shop_idx     on public.products (shop_id);
create index products_category_idx on public.products (category);

-- ---------- 4. ORDERS ----------
-- One order belongs to exactly one shop (multi-vendor carts are split per shop at checkout).
create table public.orders (
  id                uuid primary key default gen_random_uuid(),
  order_number      bigint generated always as identity,   -- human-friendly #
  customer_id       uuid not null references public.profiles(id),
  shop_id           uuid not null references public.shops(id),
  status            order_status not null default 'placed',
  subtotal          numeric(10,2) not null,
  delivery_fee      numeric(10,2) not null default 0,
  total_amount      numeric(10,2) not null,
  payment_method    payment_method not null default 'cod',
  payment_status    payment_status not null default 'pending',
  delivery_address  text not null,
  delivery_pincode  text,
  delivery_lat      double precision,
  delivery_lng      double precision,
  customer_phone    text,
  notes             text,
  created_at        timestamptz not null default now(),
  updated_at        timestamptz not null default now()
);
create index orders_customer_idx on public.orders (customer_id);
create index orders_shop_idx     on public.orders (shop_id);
create index orders_status_idx   on public.orders (status);

-- Line items (needed: an order contains many products).
-- Name/price are snapshotted so later product edits don't change history.
create table public.order_items (
  id            uuid primary key default gen_random_uuid(),
  order_id      uuid not null references public.orders(id) on delete cascade,
  product_id    uuid references public.products(id) on delete set null,
  product_name  text not null,
  unit_price    numeric(10,2) not null,
  quantity      integer not null check (quantity > 0),
  line_total    numeric(10,2) not null
);
create index order_items_order_idx on public.order_items (order_id);

-- ---------- updated_at trigger ----------
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end;
$$;

create trigger trg_profiles_updated before update on public.profiles
  for each row execute function public.set_updated_at();
create trigger trg_shops_updated before update on public.shops
  for each row execute function public.set_updated_at();
create trigger trg_products_updated before update on public.products
  for each row execute function public.set_updated_at();
create trigger trg_orders_updated before update on public.orders
  for each row execute function public.set_updated_at();

-- =====================================================
-- ROW LEVEL SECURITY (baseline; refine in later steps)
-- =====================================================
alter table public.profiles    enable row level security;
alter table public.shops       enable row level security;
alter table public.products    enable row level security;
alter table public.orders      enable row level security;
alter table public.order_items enable row level security;

-- PROFILES
create policy "own profile read"   on profiles for select using (id = auth.uid() or is_admin());
create policy "own profile update" on profiles for update using (id = auth.uid() or is_admin());
-- NOTE: stop users changing their own role via the client. Do role changes
-- from the admin panel (service role / RPC) or add a column-level check later.

-- SHOPS
create policy "public sees approved shops" on shops for select
  using (status = 'approved' or owner_id = auth.uid() or is_admin());
create policy "owner creates shop" on shops for insert with check (owner_id = auth.uid());
create policy "owner or admin updates shop" on shops for update
  using (owner_id = auth.uid() or is_admin());

-- PRODUCTS
create policy "public sees products of approved shops" on products for select using (
  exists (select 1 from shops s where s.id = shop_id
          and (s.status = 'approved' or s.owner_id = auth.uid() or is_admin()))
);
create policy "owner manages own products" on products for all using (
  exists (select 1 from shops s where s.id = shop_id and s.owner_id = auth.uid())
) with check (
  exists (select 1 from shops s where s.id = shop_id and s.owner_id = auth.uid())
);

-- ORDERS
create policy "customer/shop/admin read orders" on orders for select using (
  customer_id = auth.uid()
  or is_admin()
  or exists (select 1 from shops s where s.id = shop_id and s.owner_id = auth.uid())
);
create policy "customer places order" on orders for insert with check (customer_id = auth.uid());
create policy "shop or admin updates order" on orders for update using (
  is_admin()
  or exists (select 1 from shops s where s.id = shop_id and s.owner_id = auth.uid())
);

-- ORDER ITEMS
create policy "read items of visible orders" on order_items for select using (
  exists (select 1 from orders o where o.id = order_id and (
    o.customer_id = auth.uid() or is_admin()
    or exists (select 1 from shops s where s.id = o.shop_id and s.owner_id = auth.uid())
  ))
);
create policy "customer adds items to own order" on order_items for insert with check (
  exists (select 1 from orders o where o.id = order_id and o.customer_id = auth.uid())
);
