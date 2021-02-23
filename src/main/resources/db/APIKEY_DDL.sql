-- public.apikey create script

-- NOTE this create script assumes the schema "public"
-- otherwise, change it accordingly below

-- NOTE uncomment if you want to remove an existing APIKEY table
-- Drop table
-- DROP TABLE public.apikey;

CREATE TABLE public.apikey (
                               apikey varchar NOT NULL,
                               keycloakid varchar NULL,
                               firstname text NOT NULL,
                               lastname text NOT NULL,
                               email text NOT NULL,
                               appname text NOT NULL,
                               company text NOT NULL,
                               sector text NULL,
                               website text NULL,
                               registrationdate timestamp NOT NULL,
                               activationdate timestamp NULL,
                               lastaccessdate timestamp NULL,
                               deprecationdate timestamp NULL,
                               "comments" text NULL,
                               CONSTRAINT apikey_pk PRIMARY KEY (apikey),
                               CONSTRAINT apikey_un UNIQUE (email, appname)
);
CREATE INDEX apikey_email_idx ON public.apikey USING btree (email);

-- Permissions

ALTER TABLE public.apikey OWNER TO "admin";
GRANT ALL ON TABLE public.apikey TO "admin";