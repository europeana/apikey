-- Table: public.apikey

-- DROP TABLE public.apikey;

CREATE TABLE public.apikey
(
    apikey character varying(30) COLLATE pg_catalog."default" NOT NULL,
    activationdate date,
    appname character varying(255) COLLATE pg_catalog."default",
    company character varying(100) COLLATE pg_catalog."default",
    sector character varying(255) COLLATE pg_catalog."default",
    email character varying(100) COLLATE pg_catalog."default" NOT NULL DEFAULT 'unknown'::character varying,
    firstname character varying(50) COLLATE pg_catalog."default",
    lastname character varying(50) COLLATE pg_catalog."default",
    level character varying(8) COLLATE pg_catalog."default" NOT NULL DEFAULT 'CLIENT'::character varying,
    privatekey character varying(30) COLLATE pg_catalog."default" NOT NULL,
    registrationdate date NOT NULL DEFAULT '1980-01-01'::date,
    usagelimit bigint,
    website character varying(100) COLLATE pg_catalog."default",
    deprecationdate date,
    lastaccessdate date,
    usage bigint NOT NULL DEFAULT 0,
    description character varying(255) COLLATE pg_catalog."default",
    CONSTRAINT apikey_pkey PRIMARY KEY (apikey),
    CONSTRAINT privatekey__uk UNIQUE (privatekey)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.apikey
    OWNER to europeana;

-- Index: apikey_email_index

-- DROP INDEX public.apikey_email_index;

CREATE INDEX apikey_email_index
    ON public.apikey USING btree
    (email COLLATE pg_catalog."default")
    TABLESPACE pg_default;