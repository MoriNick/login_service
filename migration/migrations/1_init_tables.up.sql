create extension "uuid-ossp";

create table users (
    id uuid primary key,
    email text unique not null,
    nickname text unique not null,
    password text not null
);

create table sessions (
    id text primary key,
    user_id uuid references users (id) on delete cascade,
    updated_at timestamp,
    last_activity_at timestamp
);
