// NoiseHound walkthrough - corpus-breadth showcase seed
// ------------------------------------------------------------------
// A larger ACME.LOCAL environment whose edges span much of the measured
// corpus, from the loudest technique (DCSync, ~85) down to the quietest
// (MemberOf, ~2). Use it for the "scores across the whole corpus" view
// in docs/WALKTHROUGH.md.
//
// SAFE BY DESIGN: MERGE-only, no deletes, idempotent. It adds the ACME
// objects alongside anything already in your database.
//
// Seed it, then:  noisehound-writeback -i bolt://localhost:7687
//   docker exec -i <graph-db> cypher-shell -u neo4j -p <pw> < docs/seed_showcase_graph.cypher
// ------------------------------------------------------------------

MERGE (d {objectid:'S-1-5-21-ACME'})            SET d:Base, d:Domain, d.name='ACME.LOCAL', d.domain='ACME.LOCAL', d.domainsid='S-1-5-21-ACME'
MERGE (an {objectid:'S-1-5-21-ACME-1201'})      SET an:Base, an:User, an.name='ANALYST@ACME.LOCAL', an.domain='ACME.LOCAL', an.enabled=true
MERGE (hd {objectid:'S-1-5-21-ACME-1202'})      SET hd:Base, hd:User, hd.name='HELPDESK_SVC@ACME.LOCAL', hd.domain='ACME.LOCAL', hd.enabled=true
MERGE (db {objectid:'S-1-5-21-ACME-1203'})      SET db:Base, db:User, db.name='DBADMIN@ACME.LOCAL', db.domain='ACME.LOCAL', db.enabled=true
MERGE (bk {objectid:'S-1-5-21-ACME-1204'})      SET bk:Base, bk:User, bk.name='BACKUP_GMSA@ACME.LOCAL', bk.domain='ACME.LOCAL', bk.enabled=true
MERGE (cm {objectid:'S-1-5-21-ACME-1205'})      SET cm:Base, cm:User, cm.name='CA_MANAGER@ACME.LOCAL', cm.domain='ACME.LOCAL', cm.enabled=true
MERGE (it {objectid:'S-1-5-21-ACME-1301'})      SET it:Base, it:Group, it.name='IT_SUPPORT@ACME.LOCAL', it.domain='ACME.LOCAL'
MERGE (sa {objectid:'S-1-5-21-ACME-1302'})      SET sa:Base, sa:Group, sa.name='SERVER_ADMINS@ACME.LOCAL', sa.domain='ACME.LOCAL'
MERGE (ws {objectid:'S-1-5-21-ACME-2001'})      SET ws:Base, ws:Computer, ws.name='WS10@ACME.LOCAL', ws.domain='ACME.LOCAL', ws.operatingsystem='Windows 11'
MERGE (sq {objectid:'S-1-5-21-ACME-2002'})      SET sq:Base, sq:Computer, sq.name='SQL01@ACME.LOCAL', sq.domain='ACME.LOCAL', sq.operatingsystem='Windows Server 2022'
MERGE (da {objectid:'S-1-5-21-ACME-512'})       SET da:Base, da:Group, da:Tag_Tier_Zero, da.name='DOMAIN ADMINS@ACME.LOCAL', da.domain='ACME.LOCAL', da.highvalue=true, da.system_tags='admin_tier_0';

MATCH (d {objectid:'S-1-5-21-ACME'}), (an {objectid:'S-1-5-21-ACME-1201'}), (hd {objectid:'S-1-5-21-ACME-1202'}),
      (db {objectid:'S-1-5-21-ACME-1203'}), (bk {objectid:'S-1-5-21-ACME-1204'}), (cm {objectid:'S-1-5-21-ACME-1205'}),
      (it {objectid:'S-1-5-21-ACME-1301'}), (sa {objectid:'S-1-5-21-ACME-1302'}),
      (ws {objectid:'S-1-5-21-ACME-2001'}), (sq {objectid:'S-1-5-21-ACME-2002'}), (da {objectid:'S-1-5-21-ACME-512'})
MERGE (an)-[:MemberOf]->(it)              // 2   quiet
MERGE (hd)-[:MemberOf]->(it)              // 2   quiet
MERGE (it)-[:AdminTo]->(ws)               // ~25/34
MERGE (an)-[:CanRDP]->(ws)               // 45  loud
MERGE (ws)-[:HasSession]->(db)            // 20
MERGE (db)-[:MemberOf]->(sa)              // 2   quiet
MERGE (sa)-[:GenericAll]->(da)            // 40  loud
MERGE (an)-[:Kerberoast]->(db)            // 61  loud
MERGE (hd)-[:ForceChangePassword]->(db)   // 42
MERGE (db)-[:SQLAdmin]->(sq)              // 44
MERGE (cm)-[:ADCSESC1]->(da)              // 42  loud (ADCS)
MERGE (bk)-[:DCSync]->(d)                 // 85  loudest
RETURN 'showcase graph seeded (safe, additive)' AS status;
