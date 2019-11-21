-- CREATE USER europeana WITH PASSWORD 'culture';
-- CREATE DATABASE europeana;
GRANT ALL PRIVILEGES ON DATABASE europeana TO europeana;

--
-- PostgreSQL database dump
--

-- Dumped from database version 9.5.2
-- Dumped by pg_dump version 9.5.5

-- Started on 2016-11-09 13:56:18 CET

-- TOC entry 209 (class 1259 OID 4580530)
-- Name: apikey; Type: TABLE; Schema: public; Owner: europeana
--

CREATE TABLE apikey (
  apikey character varying(30) NOT NULL,
  privatekey character varying(30) NOT NULL,
  usagelimit bigint,
  appname character varying(255),
  registrationdate date DEFAULT '1980-01-01'::date NOT NULL,
  activationdate date,
  email character varying(100) DEFAULT 'unknown'::character varying NOT NULL,
  level character varying(8) DEFAULT 'CLIENT'::character varying NOT NULL,
  firstname character varying(50),
  lastname character varying(50),
  company character varying(100),
  website character varying(100),
  sector character varying (255),
  deprecationdate date,
  lastaccessdate date,
  usage bigint
);


ALTER TABLE apikey OWNER TO europeana;

--
-- TOC entry 210 (class 1259 OID 4580539)
-- Name: hibernate_sequence; Type: SEQUENCE; Schema: public; Owner: europeana
--

CREATE SEQUENCE hibernate_sequence
START WITH 1
INCREMENT BY 1
NO MINVALUE
NO MAXVALUE
CACHE 1;


ALTER TABLE hibernate_sequence OWNER TO europeana;

--

ALTER TABLE ONLY apikey
  ADD CONSTRAINT apikey_pkey PRIMARY KEY (apikey);


INSERT INTO apikey (apikey, privatekey, appname, registrationdate, activationdate, email, level, firstname, lastname, company, website)
VALUES ('ApiKeyDemo', 'verysecret', 'docker-test', '2018-03-27', '2018-03-27', 'api@europeana.eu', 'ADMIN', 'Test', 'Docker', 'europeana', 'www.europeana.eu');
