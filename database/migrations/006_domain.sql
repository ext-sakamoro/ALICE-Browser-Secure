-- Browser Secure domain tables
create table if not exists public.scan_jobs (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references auth.users(id) on delete cascade,
    target_url text not null,
    scan_type text not null default 'full' check (scan_type in ('full', 'quick', 'headers', 'content')),
    status text default 'pending',
    threat_count integer default 0,
    tracker_count integer default 0,
    ad_count integer default 0,
    privacy_score double precision,
    security_score double precision,
    results jsonb default '{}',
    created_at timestamptz default now(),
    completed_at timestamptz
);
create table if not exists public.blocklists (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references auth.users(id) on delete cascade,
    name text not null,
    list_type text not null check (list_type in ('ad', 'tracker', 'malware', 'custom')),
    pattern_count integer default 0,
    patterns text[],
    enabled boolean default true,
    created_at timestamptz default now()
);
create index idx_scan_jobs_user on public.scan_jobs(user_id);
create index idx_scan_jobs_url on public.scan_jobs(target_url);
