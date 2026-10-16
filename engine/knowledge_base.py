# -*- coding: utf-8 -*-
import json, sqlite3, threading
from datetime import datetime, timezone
class KnowledgeBase:
 def __init__(self,db_path='knowledge.db'): self.db_path=str(db_path); self._lock=threading.Lock(); self._init()
 def _connect(self):
  c=sqlite3.connect(self.db_path,timeout=15);c.row_factory=sqlite3.Row;return c
 def _init(self):
  with self._connect() as c:c.executescript('''CREATE TABLE IF NOT EXISTS entities(id INTEGER PRIMARY KEY,type TEXT NOT NULL,value TEXT NOT NULL,metadata TEXT,first_seen TEXT,last_seen TEXT,source_module TEXT,UNIQUE(type,value));CREATE TABLE IF NOT EXISTS relations(id INTEGER PRIMARY KEY,src_id INTEGER,dst_id INTEGER,kind TEXT,confidence REAL DEFAULT 1,source_module TEXT,metadata TEXT,created_at TEXT,UNIQUE(src_id,dst_id,kind));CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY,entity_id INTEGER,rule_id TEXT,severity TEXT,confidence REAL DEFAULT 50,evidence TEXT,source_module TEXT,scan_id TEXT,verified INTEGER DEFAULT 0,user_verdict TEXT,metadata TEXT,created_at TEXT);CREATE TABLE IF NOT EXISTS annotations(id INTEGER PRIMARY KEY,entity_id INTEGER,note TEXT,author TEXT,created_at TEXT);''')
 def _now(self):return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
 def upsert_entity(self,etype,value,source_module=None,metadata=None):
  if not etype or not value:return None
  now=self._now(); meta=json.dumps(metadata or {},ensure_ascii=False)
  with self._lock, self._connect() as c:
   row=c.execute('SELECT id FROM entities WHERE type=? AND value=?',(etype,str(value))).fetchone()
   if row:c.execute('UPDATE entities SET last_seen=?,source_module=?,metadata=? WHERE id=?',(now,source_module,meta,row['id']));return row['id']
   return c.execute('INSERT INTO entities(type,value,metadata,first_seen,last_seen,source_module) VALUES(?,?,?,?,?,?)',(etype,str(value),meta,now,now,source_module)).lastrowid
 def get_entity(self,etype,value):
  with self._connect() as c:
   r=c.execute('SELECT * FROM entities WHERE type=? AND value=?',(etype,str(value))).fetchone()
  return dict(r) if r else None
 def find_entities(self,etype=None,value_like=None,limit=100):
  q='SELECT * FROM entities WHERE 1=1';a=[]
  if etype:q+=' AND type=?';a.append(etype)
  if value_like:q+=' AND value LIKE ?';a.append('%'+value_like+'%')
  q+=' ORDER BY id DESC LIMIT ?';a.append(int(limit))
  with self._connect() as c:return [dict(x) for x in c.execute(q,a)]
 def add_relation(self,st,sv,dt,dv,kind,confidence=1,source_module=None,metadata=None):
  a=self.upsert_entity(st,sv,source_module);b=self.upsert_entity(dt,dv,source_module)
  with self._connect() as c:
   c.execute('INSERT OR REPLACE INTO relations(src_id,dst_id,kind,confidence,source_module,metadata,created_at) VALUES(?,?,?,?,?,?,?)',(a,b,kind,confidence,source_module,json.dumps(metadata or {}),self._now()));return c.lastrowid
 def relations_of(self,etype,value):
  e=self.get_entity(etype,value)
  if not e:return []
  with self._connect() as c:return [dict(x) for x in c.execute('SELECT r.*,s.type src_type,s.value src_value,d.type dst_type,d.value dst_value FROM relations r JOIN entities s ON s.id=r.src_id JOIN entities d ON d.id=r.dst_id WHERE r.src_id=? OR r.dst_id=?',(e['id'],e['id']))]
 def add_finding(self,etype,value,rule_id,severity,confidence=50,evidence='',source_module=None,metadata=None):
  eid=self.upsert_entity(etype,value,source_module)
  with self._connect() as c:return c.execute('INSERT INTO findings(entity_id,rule_id,severity,confidence,evidence,source_module,metadata,created_at) VALUES(?,?,?,?,?,?,?,?)',(eid,rule_id,severity,confidence,evidence,source_module,json.dumps(metadata or {}),self._now())).lastrowid
 def findings_for_entity(self,etype,value,limit=200):
  e=self.get_entity(etype,value)
  if not e:return []
  with self._connect() as c:return [dict(x) for x in c.execute('SELECT * FROM findings WHERE entity_id=? ORDER BY id DESC LIMIT ?',(e['id'],limit))]
 def add_annotation(self,etype,value,note,author=None):
  eid=self.upsert_entity(etype,value)
  with self._connect() as c:return c.execute('INSERT INTO annotations(entity_id,note,author,created_at) VALUES(?,?,?,?)',(eid,note,author,self._now())).lastrowid
 def annotations_for(self,etype,value):
  e=self.get_entity(etype,value)
  if not e:return []
  with self._connect() as c:return [dict(x) for x in c.execute('SELECT * FROM annotations WHERE entity_id=? ORDER BY id DESC',(e['id'],))]
 def set_verdict(self,finding_id,verdict):
  with self._connect() as c:c.execute('UPDATE findings SET user_verdict=?,verified=1 WHERE id=?',(verdict,finding_id))
 def stats(self):
  with self._connect() as c:return {k:c.execute('SELECT COUNT(*) FROM '+k).fetchone()[0] for k in ('entities','relations','findings','annotations')}
 def reset(self):
  with self._connect() as c:
   for t in ('annotations','findings','relations','entities'):c.execute('DELETE FROM '+t)
