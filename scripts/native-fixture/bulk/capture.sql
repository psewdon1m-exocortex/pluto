\set ON_ERROR_STOP on
\set QUIET on
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL TIME ZONE 'UTC';
SET LOCAL extra_float_digits = 3;
SELECT jsonb_build_object('kind','database','name',current_database(),'serverVersion',current_setting('server_version_num'),'encoding',current_setting('server_encoding'),'timeZone',current_setting('TimeZone'))::text;
-- Keep each complete row as opaque PostgreSQL JSON text. The orchestrator must
-- not coerce bigint/numeric/time values through JavaScript numbers.
SELECT format(
  $capture$SELECT jsonb_build_object('kind','table','name',%L,'columns',ARRAY(SELECT a.attname FROM pg_attribute a WHERE a.attrelid=%s AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum),'rows',(SELECT COALESCE(jsonb_agg(row_text ORDER BY row_text COLLATE "C"),'[]'::jsonb) FROM (SELECT row_to_json(t)::text AS row_text FROM %I.%I AS t) AS captured))::text$capture$,
  format('%I.%I',n.nspname,c.relname),c.oid,n.nspname,c.relname)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE c.relkind IN ('r','p','m') AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C"
\gexec
SELECT format($capture$SELECT jsonb_build_object('kind','sequence','name',%L,'lastValue',last_value::text,'isCalled',is_called)::text FROM %I.%I$capture$,format('%I.%I',n.nspname,c.relname),n.nspname,c.relname)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE c.relkind='S' AND n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'
ORDER BY n.nspname COLLATE "C",c.relname COLLATE "C"
\gexec
-- Globals and DDL are independently compared from complete pg_dumpall --globals-only
-- and pg_dump --schema-only exports. Only generated psql restrict/unrestrict
-- nonces may be normalized; roles/passwords/owners/grants/functions stay exact.
SELECT jsonb_build_object('kind','finished','database',current_database(),'readOnly',current_setting('transaction_read_only'),'isolation',current_setting('transaction_isolation'))::text;
COMMIT;
