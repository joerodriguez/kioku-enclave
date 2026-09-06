WITH target AS (
    SELECT relation.oid,relation.relname,relation.relkind,relation.relpersistence,
           relation.relrowsecurity,relation.relforcerowsecurity,relation.relreplident,relation.relam
      FROM pg_class relation JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
     WHERE namespace.nspname=current_schema()
       AND relation.relname LIKE 'orphan\_capture\_erasure\_%' ESCAPE '\'
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
    SELECT 'index',target.relname,concat_ws('|',index_state.indisvalid::text,
               index_state.indisready::text,index_state.indislive::text,pg_get_indexdef(target.oid))
      FROM target JOIN pg_index index_state ON index_state.indexrelid=target.oid
    UNION ALL
    SELECT 'function',function_state.proname||'('||oidvectortypes(function_state.proargtypes)||')',
           pg_get_functiondef(function_state.oid)
      FROM pg_proc function_state JOIN pg_namespace namespace ON namespace.oid=function_state.pronamespace
     WHERE namespace.nspname=current_schema()
       AND function_state.proname LIKE 'orphan\_capture\_erasure\_%' ESCAPE '\'
    UNION ALL
    SELECT 'trigger',relation.relname||'.'||trigger_state.tgname,
           concat_ws('|',trigger_state.tgenabled::text,pg_get_triggerdef(trigger_state.oid,true))
      FROM pg_trigger trigger_state JOIN pg_class relation ON relation.oid=trigger_state.tgrelid
      JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
     WHERE namespace.nspname=current_schema() AND NOT trigger_state.tgisinternal
       AND (trigger_state.tgname LIKE 'orphan\_capture\_erasure\_%' ESCAPE '\'
            OR relation.relname LIKE 'orphan\_capture\_erasure\_%' ESCAPE '\')
    UNION ALL
    SELECT 'policy',target.relname||'.'||policy.polname,
           concat_ws('|',policy.polpermissive::text,policy.polcmd::text,
               policy.polroles::text,coalesce(pg_get_expr(policy.polqual,policy.polrelid,true),''),
               coalesce(pg_get_expr(policy.polwithcheck,policy.polrelid,true),''))
      FROM target JOIN pg_policy policy ON policy.polrelid=target.oid
)
SELECT coalesce(string_agg(kind||chr(31)||name||chr(31)||definition,chr(30)
                          ORDER BY kind,name,definition),'') FROM evidence
