// NoiseHound walkthrough - safe demo-graph seed
// ------------------------------------------------------------------
// Seeds the small CORP.LOCAL two-route scenario used in
// docs/WALKTHROUGH.md so you can reproduce the screenshots offline.
//
// SAFE BY DESIGN: this script only MERGEs (creates-if-absent) six nodes
// and five relationships. It performs NO delete and touches nothing
// else in your database - running it twice is a no-op, and running it
// against a populated graph just adds these demo objects alongside your
// data. (It does not wipe anything. Ever.)
//
// It models two competing routes from JDOE to Domain Admins:
//   * a quiet 4-hop path : MemberOf -> AdminTo -> HasSession -> MemberOf
//   * a loud  2-hop path : GenericAll -> MemberOf
// NoiseHound ranks the 4-hop path as the quietest (see the walkthrough).
//
// NOTE: on a REAL engagement you do not need this at all - just point
// NoiseHound at your own SharpHound collection or live Neo4j. This seed
// exists only because a hand-authored micro-sample does not round-trip
// computer/session edges (AdminTo, HasSession) through BloodHound CE's
// ingestion; a real collection carries them natively.
//
// Run with the BHCE Neo4j password (NEO4J_SECRET in your bloodhound .env;
// community default `bloodhoundcommunityedition`):
//   docker exec -i <graph-db> cypher-shell -u neo4j -p <pw> < docs/seed_demo_graph.cypher
// ------------------------------------------------------------------

// --- Nodes (idempotent MERGE on objectid; sets BHCE labels + properties) ---
MERGE (d {objectid:'S-1-5-21-CORP'})
  SET d:Base, d:Domain, d.name='CORP.LOCAL', d.domain='CORP.LOCAL', d.domainsid='S-1-5-21-CORP'
MERGE (jdoe {objectid:'S-1-5-21-CORP-1104'})
  SET jdoe:Base, jdoe:User, jdoe.name='JDOE@CORP.LOCAL', jdoe.domain='CORP.LOCAL', jdoe.domainsid='S-1-5-21-CORP', jdoe.enabled=true
MERGE (help {objectid:'S-1-5-21-CORP-1105'})
  SET help:Base, help:Group, help.name='HELPDESK@CORP.LOCAL', help.domain='CORP.LOCAL', help.domainsid='S-1-5-21-CORP'
MERGE (wk1 {objectid:'S-1-5-21-CORP-1106'})
  SET wk1:Base, wk1:Computer, wk1.name='WK1@CORP.LOCAL', wk1.domain='CORP.LOCAL', wk1.domainsid='S-1-5-21-CORP', wk1.operatingsystem='Windows 10'
MERGE (svc {objectid:'S-1-5-21-CORP-1107'})
  SET svc:Base, svc:User, svc.name='SVC@CORP.LOCAL', svc.domain='CORP.LOCAL', svc.domainsid='S-1-5-21-CORP', svc.enabled=true
MERGE (da {objectid:'S-1-5-21-CORP-512'})
  SET da:Base, da:Group, da:Tag_Tier_Zero, da.name='DOMAIN ADMINS@CORP.LOCAL', da.domain='CORP.LOCAL', da.domainsid='S-1-5-21-CORP', da.highvalue=true, da.system_tags='admin_tier_0';

// --- Relationships (idempotent MERGE) ---
MATCH (jdoe {objectid:'S-1-5-21-CORP-1104'}), (help {objectid:'S-1-5-21-CORP-1105'}),
      (wk1  {objectid:'S-1-5-21-CORP-1106'}), (svc  {objectid:'S-1-5-21-CORP-1107'}),
      (da   {objectid:'S-1-5-21-CORP-512'})
MERGE (jdoe)-[:MemberOf]->(help)     // quiet route, hop 1
MERGE (help)-[:AdminTo]->(wk1)       // quiet route, hop 2
MERGE (wk1)-[:HasSession]->(svc)     // quiet route, hop 3
MERGE (svc)-[:MemberOf]->(da)        // shared final hop
MERGE (jdoe)-[:GenericAll]->(svc)    // loud 2-hop shortcut
RETURN 'demo graph seeded (safe, additive)' AS status;
