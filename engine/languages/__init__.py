# -*- coding: utf-8 -*-
from .base import Rule,FrameworkPack,LanguageBranch,BestPractice,LanguageModule,SEVERITY_ORDER,SEVERITIES,sec,eng,perf,style
from . import registry,cross_index
def get(name):return registry.get(name)
def all_languages():return registry.all_languages()
def list_names():return registry.list_names()
def detect(filename):return registry.detect(filename)
def all_metadata():return registry.all_metadata()
def all_frameworks():return registry.all_frameworks()
def stats():return registry.stats()
def reload():return registry.reload()
def cwe_rules(cwe):return cross_index.lookup_cwe(cwe)
def owasp_rules(oid):return cross_index.lookup_owasp(oid)
def similar_in_other_languages(rid):return cross_index.similar_rules(rid)
def cross_summary():return cross_index.summary()
def by_category(cat):return cross_index.by_category(cat)
