# -*- coding: utf-8 -*-
import json
class RuleStore:
 def __init__(self,db):self.db=db
 def _norm(self,r):
  if not isinstance(r,dict) or not r.get('id') or not (r.get('title') or r.get('name')):return None
  return {**r,'title':r.get('title') or r.get('name'),'languages':json.dumps(r.get('languages',['*'])),'frameworks':json.dumps(r.get('frameworks')) if r.get('frameworks') else None,'severity':r.get('severity','medium')}
 def add(self,r):
  r=self._norm(r)
  if not r:return False
  cols=['id','source','category','languages','frameworks','severity','cwe','owasp','cve','title','description','pattern','remediation','confidence','enabled']
  self.db.execute(f"INSERT OR REPLACE INTO rules({','.join(cols)}) VALUES({','.join('?' for _ in cols)})",[r.get(k) for k in cols]);self.db.conn.commit();return True
 def get(self,rid):return self.db.fetchone('SELECT * FROM rules WHERE id=?',(rid,))
 def search(self,language=None,severity=None,category=None,text=None,limit=100,offset=0):
  q='SELECT * FROM rules WHERE enabled=1';a=[]
  if language:q+=' AND (languages LIKE ? OR languages LIKE ?)';a += [f'%"{language}"%','%"*"%']
  if severity:q+=' AND severity=?';a.append(severity)
  if category:q+=' AND category=?';a.append(category)
  if text:q+=' AND (title LIKE ? OR description LIKE ?)';a += [f'%{text}%',f'%{text}%']
  q+=' ORDER BY id LIMIT ? OFFSET ?';a += [limit,offset];return self.db.fetchall(q,a)
 def count(self):return int(self.db.scalar('SELECT COUNT(*) FROM rules') or 0)
 def add_many(self,rs):return sum(self.add(r) for r in rs)
