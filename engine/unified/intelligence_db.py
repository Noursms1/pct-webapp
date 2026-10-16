# -*- coding: utf-8 -*-
import sqlite3,threading
from pathlib import Path
from contextlib import contextmanager
MIGRATIONS=Path(__file__).parent/'migrations'
class IntelligenceDB:
 def __init__(self,path):self.path=str(path);self.local=threading.local();Path(path).parent.mkdir(parents=True,exist_ok=True);self._ensure()
 def _connect(self):
  c=sqlite3.connect(self.path,timeout=15,check_same_thread=False);c.row_factory=sqlite3.Row;c.execute('PRAGMA journal_mode=WAL');return c
 @property
 def conn(self):
  if not hasattr(self.local,'conn'):self.local.conn=self._connect()
  return self.local.conn
 def close(self):
  if hasattr(self.local,'conn'):self.local.conn.close();del self.local.conn
 def _ensure(self):
  c=self._connect();c.execute('CREATE TABLE IF NOT EXISTS schema_migrations(name TEXT PRIMARY KEY)')
  applied={r[0] for r in c.execute('SELECT name FROM schema_migrations')}
  for p in sorted(MIGRATIONS.glob('*.sql')):
   if p.name not in applied:c.executescript(p.read_text(encoding='utf-8'));c.execute('INSERT INTO schema_migrations VALUES(?)',(p.name,))
  c.commit();c.close()
 def applied_migrations(self):return [r[0] for r in self.conn.execute('SELECT name FROM schema_migrations ORDER BY name')]
 def execute(self,sql,params=()):return self.conn.execute(sql,tuple(params))
 def fetchone(self,sql,params=()):
  r=self.conn.execute(sql,tuple(params)).fetchone();return dict(r) if r else None
 def fetchall(self,sql,params=()):return [dict(r) for r in self.conn.execute(sql,tuple(params))]
 def scalar(self,sql,params=()):
  r=self.conn.execute(sql,tuple(params)).fetchone();return r[0] if r else None
 @contextmanager
 def transaction(self):
  self.conn.execute('BEGIN')
  try:yield self.conn;self.conn.execute('COMMIT')
  except Exception:self.conn.execute('ROLLBACK');raise
