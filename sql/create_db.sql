-- Database: testdb

-- DROP DATABASE IF EXISTS testdb;

CREATE DATABASE testdb
    WITH
    OWNER = postgres
    ENCODING = 'UTF8'
    LC_COLLATE = 'Russian_Russia.1251'
    LC_CTYPE = 'Russian_Russia.1251'
    LOCALE_PROVIDER = 'libc'
    TABLESPACE = pg_default
    CONNECTION LIMIT = -1
    IS_TEMPLATE = False;
    
-- Type: incomerangeenum

-- DROP TYPE IF EXISTS public.incomerangeenum;

CREATE TYPE public.incomerangeenum AS ENUM
    ('<30k', '30-70k', '>70k');

ALTER TYPE public.incomerangeenum
    OWNER TO postgres;


CREATE TYPE public.educationenum AS ENUM
    ('school', 'college', 'master', 'phd');

ALTER TYPE public.educationenum
    OWNER TO postgres;


-- Table: public.users

-- DROP TABLE IF EXISTS public.users;

CREATE TABLE IF NOT EXISTS public.users
(
    id uuid NOT NULL,
    email character varying COLLATE pg_catalog."default" NOT NULL,
    password_hash character varying COLLATE pg_catalog."default" NOT NULL,
    name character varying COLLATE pg_catalog."default" NOT NULL,
    bio character varying COLLATE pg_catalog."default",
    "avatarUrl" character varying COLLATE pg_catalog."default",
    "incomeRange" incomerangeenum,
    "education" educationenum,
    "createdAt" timestamp without time zone,
    "updatedAt" timestamp without time zone,
    CONSTRAINT users_pkey PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.users
    OWNER to postgres;
-- Index: ix_users_email

-- DROP INDEX IF EXISTS public.ix_users_email;

CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email
    ON public.users USING btree
    (email COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: ix_users_id

-- DROP INDEX IF EXISTS public.ix_users_id;

CREATE INDEX IF NOT EXISTS ix_users_id
    ON public.users USING btree
    (id ASC NULLS LAST)
    TABLESPACE pg_default;