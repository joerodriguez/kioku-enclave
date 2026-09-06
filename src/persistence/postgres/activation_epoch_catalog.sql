WITH target AS (
    SELECT relation.oid,relation.relname,relation.relkind,relation.relpersistence,
           relation.relrowsecurity,relation.relforcerowsecurity,relation.relreplident,relation.relam
      FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
     WHERE namespace.nspname=current_schema()
       AND relation.relname LIKE 'reconciliation\_activation\_epoch\_%' ESCAPE '\'
), evidence(kind,name,definition) AS (
    SELECT 'relation',relname,concat_ws('|',relkind::text,relpersistence::text,
        relrowsecurity::text,relforcerowsecurity::text,relreplident::text,relam::text) FROM target
    UNION ALL
    SELECT 'column',target.relname||'.'||attribute.attname,
           concat_ws('|',attribute.attnum::text,format_type(attribute.atttypid,attribute.atttypmod),
               attribute.attnotnull::text,attribute.attidentity::text,attribute.attgenerated::text,
               attribute.attcollation::text,
               coalesce(pg_get_expr(default_value.adbin,default_value.adrelid,true),''))
      FROM target JOIN pg_attribute attribute ON attribute.attrelid=target.oid
       AND attribute.attnum>0 AND NOT attribute.attisdropped
      LEFT JOIN pg_attrdef default_value ON default_value.adrelid=target.oid
       AND default_value.adnum=attribute.attnum
     WHERE target.relkind IN ('r','p')
    UNION ALL
    SELECT 'constraint',target.relname||'.'||constraint_state.conname,
           concat_ws('|',constraint_state.contype::text,constraint_state.convalidated::text,
               constraint_state.condeferrable::text,constraint_state.condeferred::text,
               pg_get_constraintdef(constraint_state.oid,true))
      FROM target JOIN pg_constraint constraint_state ON constraint_state.conrelid=target.oid
    UNION ALL
    SELECT 'index',index_relation.relname,concat_ws('|',index_state.indisvalid::text,
               index_state.indisready::text,index_state.indislive::text,pg_get_indexdef(index_relation.oid))
      FROM pg_index index_state JOIN pg_class index_relation ON index_relation.oid=index_state.indexrelid
     WHERE index_state.indrelid IN (SELECT oid FROM target)
        OR index_state.indexrelid IN (SELECT oid FROM target)
    UNION ALL
    SELECT 'type',type_state.typname,concat_ws('|',type_state.typtype::text,
               type_state.typcategory::text,type_state.typnotnull::text,
               CASE WHEN type_state.typbasetype=0 THEN '' ELSE format_type(type_state.typbasetype,type_state.typtypmod) END,
               CASE WHEN type_state.typelem=0 THEN '' ELSE format_type(type_state.typelem,NULL) END,
               coalesce(type_state.typdefault,''),
               coalesce((SELECT jsonb_agg(enum_state.enumlabel ORDER BY enum_state.enumsortorder)::text
                         FROM pg_enum enum_state WHERE enum_state.enumtypid=type_state.oid),'[]'))
      FROM pg_type type_state JOIN pg_namespace namespace ON namespace.oid=type_state.typnamespace
     WHERE namespace.nspname=current_schema()
       AND (type_state.typname LIKE 'reconciliation\_activation\_epoch\_%' ESCAPE '\'
            OR type_state.typname LIKE '\_reconciliation\_activation\_epoch\_%' ESCAPE '\')
    UNION ALL
    SELECT 'function',function_state.proname||'('||oidvectortypes(function_state.proargtypes)||')',
           pg_get_functiondef(function_state.oid)
      FROM pg_proc function_state JOIN pg_namespace namespace ON namespace.oid=function_state.pronamespace
     WHERE namespace.nspname=current_schema()
       AND function_state.proname LIKE 'reconciliation\_activation\_epoch\_%' ESCAPE '\'
    UNION ALL
    SELECT 'trigger',relation.relname||'.'||trigger_state.tgname,
           concat_ws('|',trigger_state.tgenabled::text,pg_get_triggerdef(trigger_state.oid,true))
      FROM pg_trigger trigger_state JOIN pg_class relation ON relation.oid=trigger_state.tgrelid
      JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
     WHERE namespace.nspname=current_schema() AND NOT trigger_state.tgisinternal
       AND (trigger_state.tgname LIKE 'reconciliation\_activation\_epoch\_%' ESCAPE '\'
            OR relation.relname LIKE 'reconciliation\_activation\_epoch\_%' ESCAPE '\')
    UNION ALL
    SELECT 'policy',target.relname||'.'||policy.polname,
           concat_ws('|',policy.polpermissive::text,policy.polcmd::text,
               policy.polroles::text,coalesce(pg_get_expr(policy.polqual,policy.polrelid,true),''),
               coalesce(pg_get_expr(policy.polwithcheck,policy.polrelid,true),''))
      FROM target JOIN pg_policy policy ON policy.polrelid=target.oid
)
SELECT coalesce(jsonb_agg(jsonb_build_array(kind,name,definition)
                         ORDER BY kind,name,definition),'[]'::jsonb)::text FROM evidence
