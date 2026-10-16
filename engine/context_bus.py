# -*- coding: utf-8 -*-
from .knowledge_base import KnowledgeBase
_BUS=None
def get_bus(path='knowledge.db'):
 global _BUS
 if _BUS is None:_BUS=ContextBus(path)
 return _BUS
class ContextBus:
 def __init__(self,path):self.kb=KnowledgeBase(path)
 def register_target(self,target,source):return self.kb.upsert_entity('domain',target,source)
 def get_context_for(self,target):
  return {'entity':self.kb.get_entity('domain',target) or self.kb.get_entity('target',target),'findings':self.kb.findings_for_entity('domain',target),'relations':self.kb.relations_of('domain',target),'annotations':self.kb.annotations_for('domain',target)}
 def register_subdomain(self,domain,subdomain,source):return self.kb.add_relation('domain',domain,'subdomain',subdomain,'contains',source_module=source)
