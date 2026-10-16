# -*- coding: utf-8 -*-
import sqlite3,threading
from datetime import datetime,timezone
class RulesStore:
 def __init__(self,db_path="rules.db"):self.db_path=str(db_path);self._lock=threading.Lock();self._init()
 def _connect(self):
  c=sqlite3.connect(self.db_path,timeout=10);c.row_factory=sqlite3.Row;return c
 def _init(self):
  with self._connect() as c:c.executescript('''CREATE TABLE IF NOT EXISTS pdf_sources(id INTEGER PRIMARY KEY,filename TEXT,sha256 TEXT UNIQUE,pages INTEGER,chars INTEGER,language TEXT,uploaded_at TEXT,rules_count INTEGER DEFAULT 0);CREATE TABLE IF NOT EXISTS custom_rules(id INTEGER PRIMARY KEY,rule_id TEXT UNIQUE,name TEXT,language TEXT,severity TEXT,cwe TEXT,pattern_raw TEXT,description TEXT,fix TEXT,source_pdf_id INTEGER,enabled INTEGER DEFAULT 1,strict INTEGER DEFAULT 1,created_at TEXT);CREATE INDEX IF NOT EXISTS idx_rules_lang ON custom_rules(language);''')
 def add_pdf_source(self,filename,sha256,pages,chars,language=None,notes=None):
  try:
   with self._connect() as c:c.execute('INSERT INTO pdf_sources(filename,sha256,pages,chars,language,uploaded_at) VALUES(?,?,?,?,?,?)',(filename,sha256,pages,chars,language,datetime.now(timezone.utc).isoformat()));return c.execute('SELECT last_insert_rowid()').fetchone()[0]
  except sqlite3.IntegrityError:return None
 def list_pdf_sources(self):
  with self._connect() as c:return [dict(r) for r in c.execute('SELECT * FROM pdf_sources ORDER BY id DESC')]
 def add_rule(self,r,source_pdf_id=None,enabled=True,strict=True):
  try:
   with self._connect() as c:c.execute('INSERT INTO custom_rules(rule_id,name,language,severity,cwe,pattern_raw,description,fix,source_pdf_id,enabled,strict,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',(r['id'],r['name'],r.get('language'),r['severity'],r.get('cwe'),r.get('pattern_raw'),r.get('desc'),r.get('fix'),source_pdf_id,int(enabled),int(strict),datetime.now(timezone.utc).isoformat()));return True
  except sqlite3.IntegrityError:return False
 def add_rules_bulk(self,rules,source_pdf_id=None):
  a=sum(self.add_rule(r,source_pdf_id) for r in rules);return {'added':a,'skipped':len(rules)-a}
 def list_rules(self,language=None,enabled_only=True):
  q='SELECT * FROM custom_rules WHERE 1=1';args=[]
  if language:q+=' AND language=?';args.append(language)
  if enabled_only:q+=' AND enabled=1'
  with self._connect() as c:return [dict(r) for r in c.execute(q,args)]
 def set_rule_enabled(self,rid,enabled):
  with self._connect() as c:c.execute('UPDATE custom_rules SET enabled=? WHERE rule_id=?',(int(enabled),rid))
 def delete_rule(self,rid):
  with self._connect() as c:c.execute('DELETE FROM custom_rules WHERE rule_id=?',(rid,))
 def delete_pdf_source(self,pid):
  with self._connect() as c:c.execute('DELETE FROM custom_rules WHERE source_pdf_id=?',(pid,));c.execute('DELETE FROM pdf_sources WHERE id=?',(pid,))
 def stats(self):
  with self._connect() as c:return {'pdfs':c.execute('SELECT COUNT(*) FROM pdf_sources').fetchone()[0],'rules':c.execute('SELECT COUNT(*) FROM custom_rules').fetchone()[0],'enabled':c.execute('SELECT COUNT(*) FROM custom_rules WHERE enabled=1').fetchone()[0],'references':0}
