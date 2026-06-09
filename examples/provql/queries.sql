-- Find suspicious reads of sensitive files
MATCH (p:Process)-[:READ]->(f:File)
WHERE f.path = '/etc/shadow'
RETURN p.pid, p.comm, f.path

-- Find outbound SSH activity
MATCH (p:Process)-[:CONNECTED]->(n:Network)
WHERE n.label CONTAINS ':22' AND p.comm = 'ssh'
RETURN p.pid, p.comm, n.label

-- Find curl -> temp file -> shell execution chains
MATCH (a:Process)-[:WROTE]->(f:File)-[:READ]->(b:Process)
WHERE f.path STARTSWITH '/tmp'
  AND a.comm CONTAINS 'curl'
  AND b.comm = 'bash'
RETURN a.comm, f.path, b.comm

-- Find recent network exfiltration candidates
MATCH (p:Process)-[:CONNECTED]->(n:Network)
WHERE p.comm IN ['curl', 'wget', 'python', 'scp']
RETURN p.pid, p.comm, n.label
