# Using NoiseHound scores inside BloodHound (Cypher)

After `noisehound-writeback` stamps `r.noise` (0-100) onto the BloodHound CE
Neo4j relationships, you can see and query paths by detection noise directly in
the BloodHound UI. Paste these into the BloodHound "Cypher" search box or run
them in the Neo4j browser.

> These read the `noise` property written back by NoiseHound. Run
> `noisehound-writeback -i bolt://localhost:7687` first.

### Loudest edges on the graph
```cypher
MATCH (a)-[r]->(b) WHERE r.noise >= 60
RETURN a, r, b LIMIT 200
```

### Quiet control edges (the blind spots)
```cypher
MATCH (a)-[r]->(b) WHERE r.noise IS NOT NULL AND r.noise <= 20
RETURN a, r, b LIMIT 200
```

### Edges NoiseHound had no corpus entry for (defaulted)
```cypher
MATCH (a)-[r]->(b) WHERE r.noise_known = false
RETURN DISTINCT type(r) AS edge, count(*) AS n ORDER BY n DESC
```

### Total noise along the shortest path to Domain Admins
```cypher
MATCH p = shortestPath((u:User {name:"JDOE@CONTOSO.LOCAL"})-[*1..8]->(g:Group))
WHERE g.objectid ENDS WITH "-512"
RETURN [rel IN relationships(p) | rel.noise] AS edge_noise,
       reduce(s = 0.0, rel IN relationships(p) | s + coalesce(rel.noise, 60)) AS total_noise
```

### Noise-weighted quietest path (requires APOC) - Neo4j browser only
`apoc.algo.dijkstra` treats `noise` as edge cost, so this returns the genuinely
quietest route (lowest summed noise) rather than the shortest. **Even with APOC
loaded, the BloodHound CE Cypher search box rejects this** - its
`/api/v2/graphs/cypher` endpoint disallows `CALL`/procedure invocation for
safety. Run it in the **Neo4j browser**, not the BHCE UI:
```cypher
MATCH (start:User {name:"JDOE@CONTOSO.LOCAL"}),
      (end:Group) WHERE end.objectid ENDS WITH "-512"
CALL apoc.algo.dijkstra(start, end, ">", "noise") YIELD path, weight
RETURN path, weight ORDER BY weight LIMIT 5
```

### Noise-weighted quietest path - BHCE Cypher box (no APOC, no `CALL`)
Same idea, pure Cypher: enumerate bounded paths and rank by summed noise. This
**does** run in the BloodHound CE search box:
```cypher
MATCH p=(start:User {name:"JDOE@CONTOSO.LOCAL"})-[*1..5]->(end:Group)
WHERE end.objectid ENDS WITH "-512"
WITH p, reduce(s=0.0, r IN relationships(p) | s + coalesce(r.noise, 60)) AS noise
RETURN p ORDER BY noise ASC LIMIT 1
```
This enumerates every path up to the hop cap, so keep `*1..5`/`*1..6` - fine at
lab scale, not for unbounded enumeration on a large graph.

> **APOC is not loaded by the default BloodHound CE stack.** The neo4j image
> bundles a version-matched `apoc-<ver>-core.jar` under `/var/lib/neo4j/labs`,
> but the BHCE compose file does not copy it into `plugins/`, so `apoc.*`
> procedures are not registered until you enable them. On the `graph-db`
> container:
>
> ```bash
> docker exec -u root <graph-db> sh -c '\
>   cp /var/lib/neo4j/labs/apoc-*-core.jar /var/lib/neo4j/plugins/ && \
>   chown neo4j:neo4j /var/lib/neo4j/plugins/apoc-*-core.jar && \
>   echo "dbms.security.procedures.unrestricted=apoc.*" >> /var/lib/neo4j/conf/neo4j.conf'
> docker restart <graph-db>
> ```
>
> Verify with `SHOW PROCEDURES YIELD name WHERE name STARTS WITH "apoc"`. If you
> would rather not enable APOC, the **shortest-path total-noise** query above
> needs no plugins and works on a stock stack.

> Note: this is a convenience view. For the full model - the max/mean path score,
> detection probability, Pareto trade-offs, and the blue-team gap report - use
> the `noisehound` CLI, which reads the same Neo4j (`-i bolt://...`).
