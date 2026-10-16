# -*- coding: utf-8 -*-
"""Java security and engineering knowledge base."""
from .base import FrameworkPack, LanguageBranch, BestPractice, LanguageModule, sec, eng

SECURITY=[
 sec('JAVA-SEC-SQLI-01','Statement concat','critical',r'\.(?:executeQuery|executeUpdate|execute)\s*\([^)]*\+', 'SQL concatenation.','Use PreparedStatement',cwe='CWE-89'),
 sec('JAVA-SEC-SQLI-02','JPA query concat','critical',r'\.create(?:Native)?Query\s*\([^)]*\+', 'JPA query concatenation.','Use named parameters',cwe='CWE-89'),
 sec('JAVA-SEC-CMDI-01','Runtime.exec','critical',r'Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(', 'Command execution.','Use ProcessBuilder args',cwe='CWE-78'),
 sec('JAVA-SEC-CMDI-02','ProcessBuilder concat','critical',r'new\s+ProcessBuilder\s*\([^)]*\+', 'Command args concatenated.','Pass separate arguments',cwe='CWE-78'),
 sec('JAVA-SEC-DESER-01','ObjectInputStream','critical',r'ObjectInputStream|readObject\s*\(\s*\)', 'Unsafe deserialization.','Use JSON/Protobuf',cwe='CWE-502'),
 sec('JAVA-SEC-XXE-01','DocumentBuilderFactory','high',r'DocumentBuilderFactory\.newInstance', 'XXE risk.','Disable external entities',cwe='CWE-611'),
 sec('JAVA-SEC-PATH-01','File concat','high',r'new\s+File\s*\([^)]*\+', 'Path traversal.','Normalize and validate base',cwe='CWE-22'),
 sec('JAVA-SEC-SSRF-01','Dynamic URL','critical',r'new\s+URL\s*\([^)]*\+', 'SSRF risk.','Whitelist domains',cwe='CWE-918'),
 sec('JAVA-SEC-SPEL-01','SpEL parser','critical',r'SpelExpressionParser|parseExpression\s*\([^)]*\+', 'Expression injection.','Do not evaluate user input',cwe='CWE-917'),
 sec('JAVA-SEC-CRYPTO-01','MD5/SHA1','medium',r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-?1)', 'Weak hash.','Use SHA-256+',cwe='CWE-327'),
 sec('JAVA-SEC-CRYPTO-02','DES cipher','high',r'Cipher\.getInstance\s*\(\s*["\']DES', 'Weak cipher.','Use AES-GCM',cwe='CWE-327'),
 sec('JAVA-SEC-RAND-01','java.util.Random','medium',r'new\s+(?:java\.util\.)?Random\s*\(', 'Predictable random.','Use SecureRandom',cwe='CWE-338'),
 sec('JAVA-SEC-TLS-01','TrustAllCerts','critical',r'TrustAllCerts|X509TrustManager', 'TLS verification bypass.','Use default trust store',cwe='CWE-295'),
 sec('JAVA-SEC-TLS-02','Hostname verifier bypass','critical',r'HostnameVerifier|return\s+true', 'Hostname verification risk.','Use default verifier',cwe='CWE-295'),
 sec('JAVA-SEC-JWT-01','JWT none','critical',r'Algorithm\.NONE|\bnone\b.*JWT', 'JWT signature bypass.','Enforce algorithms',cwe='CWE-347'),
 sec('JAVA-SEC-JWT-02','JWT hardcoded secret','high',r'signWith\s*\([^,)]*,\s*["\'][^"\']{6,}', 'Hardcoded JWT secret.','Use KMS/env',cwe='CWE-798'),
 sec('JAVA-SEC-SECRET-01','Hardcoded secret','high',r'String\s+\w*(?:password|secret|apiKey|token)\w*\s*=\s*"[^"]{6,}"', 'Hardcoded credential.','Use environment secrets',cwe='CWE-798'),
 sec('JAVA-SEC-LOG-01','Log injection','low',r'log(?:ger)?\.(?:info|warn|error|debug)\s*\([^)]*\+', 'Log injection.','Sanitize CR/LF',cwe='CWE-117'),
 sec('JAVA-SEC-LDAP-01','LDAP concat','high',r'\.search\s*\([^)]*\+', 'LDAP injection.','Escape LDAP values',cwe='CWE-90'),
 sec('JAVA-SEC-CSRF-01','CSRF disabled','high',r'\.csrf\s*\(\s*\)\s*\.disable', 'CSRF disabled.','Keep enabled for browser apps',cwe='CWE-352'),
 sec('JAVA-SEC-ACTUATOR-01','Actuator wildcard','critical',r'exposure\.include\s*=\s*\*', 'Actuator fully exposed.','Expose only health/info',cwe='CWE-200'),
 sec('JAVA-SEC-XML-01','SAX parser','high',r'SAXParserFactory\.newInstance', 'XML entity risk.','Harden parser',cwe='CWE-611'),
 sec('JAVA-SEC-REFLECT-01','Dynamic Class.forName','high',r'Class\.forName\s*\([^)]*(?:request|input|user)', 'Dynamic class loading.','Use allowlist',cwe='CWE-470'),
 sec('JAVA-SEC-CORS-01','CORS wildcard','critical',r'allowedOrigins\s*\(\s*["\']\*["\']', 'Wildcard CORS.','Whitelist origins',cwe='CWE-942'),
 sec('JAVA-SEC-XPATH-01','XPath concat','high',r'\.evaluate\s*\([^)]*\+', 'XPath injection.','Use variables',cwe='CWE-643'),
 sec('JAVA-SEC-DESER-02','XMLDecoder','critical',r'XMLDecoder\s*\(', 'XMLDecoder code execution.','Avoid XMLDecoder',cwe='CWE-502'),
 sec('JAVA-SEC-STRUTS-01','OGNL','critical',r'Ognl\.(?:getValue|setValue|parseExpression)', 'OGNL injection.','Upgrade and restrict OGNL',cwe='CWE-917'),
 sec('JAVA-SEC-PASSWORD-01','NoOpPasswordEncoder','critical',r'NoOpPasswordEncoder', 'Plaintext password encoding.','Use BCrypt',cwe='CWE-256'),
 sec('JAVA-SEC-H2-01','H2 console enabled','high',r'spring\.h2\.console\.enabled\s*=\s*true', 'H2 console exposed.', 'Disable in production',cwe='CWE-489'),
 sec('JAVA-SEC-PROCESS-01','Shell command','critical',r'ProcessBuilder\s*\([^)]*["\'](?:sh|bash|cmd)', 'Shell invocation.', 'Call executable directly',cwe='CWE-78'),
]
ENGINEERING=[eng('JAVA-ENG-STRING-01','String ==','medium',r'\b\w+\s*==\s*["\']','Reference comparison.','Use equals()'),eng('JAVA-ENG-CATCH-01','Empty catch','medium',r'catch\s*\([^)]*\)\s*\{\s*\}','Swallowed exception.','Log or rethrow'),eng('JAVA-ENG-CATCH-02','Broad catch','medium',r'catch\s*\(\s*(?:Exception|Throwable)','Broad exception.','Catch specific types'),eng('JAVA-ENG-RESOURCE-01','Resource without try','medium',r'new\s+(?:FileInputStream|Connection)\s*\(','Resource leak risk.','Use try-with-resources'),eng('JAVA-ENG-SYSTEM-01','System.out','low',r'System\.out\.print','Use logger.','Use SLF4J'),eng('JAVA-ENG-RANDOM-01','Random object','low',r'new\s+Random\s*\(','Review randomness.','Use SecureRandom'),eng('JAVA-ENG-TODO-01','TODO','info',r'//\s*(?:TODO|FIXME)','Unresolved marker.','Create issue'),eng('JAVA-ENG-WILD-01','Wildcard import','low',r'import\s+[\w.]+\*;','Wildcard import.','Import explicit classes'),eng('JAVA-ENG-SLEEP-01','Thread.sleep','low',r'Thread\.sleep\s*\(','Sleep in production.','Use scheduler'),eng('JAVA-ENG-GENERIC-01','Generic exception','low',r'throw\s+new\s+(?:Exception|RuntimeException)','Generic exception.','Use specific type')]
SPRING=FrameworkPack('Spring Boot','3.x','https://spring.io/projects/spring-boot',[sec('JAVA-SB-01','Actuator exposure','critical',r'exposure\.include\s*=\s*\*','Actuator exposed.','Restrict endpoints',cwe='CWE-200'),sec('JAVA-SB-02','H2 console','high',r'spring\.h2\.console\.enabled\s*=\s*true','H2 console.','Disable in prod',cwe='CWE-489')])
SPRING_SECURITY=FrameworkPack('Spring Security','6.x','https://spring.io/projects/spring-security',[sec('JAVA-SS-01','CSRF disabled','high',r'\.csrf\s*\(\s*\)\s*\.disable','CSRF off.','Keep enabled',cwe='CWE-352'),sec('JAVA-SS-02','permitAll','high',r'\.permitAll\s*\(\s*\)','Public route.','Require auth',cwe='CWE-306')])
HIBERNATE=FrameworkPack('Hibernate/JPA','6.x','https://hibernate.org/',[sec('JAVA-HIB-01','HQL concat','critical',r'createQuery\s*\([^)]*\+','HQL injection.','Named params',cwe='CWE-89')])
STRUTS=FrameworkPack('Struts','2.x','https://struts.apache.org/',[sec('JAVA-STR-01','OGNL','critical',r'Ognl\.', 'OGNL injection.','Upgrade Struts',cwe='CWE-917')])
BRANCHES=[LanguageBranch('web_backend','Spring APIs',focus=['SQLi','Auth'],top_risks=['SQLi'],rule_ids=['JAVA-SEC-SQLI-01','JAVA-SEC-SSRF-01','JAVA-SB-01']),LanguageBranch('desktop','Desktop Java',focus=['Files'],top_risks=['RCE'],rule_ids=['JAVA-SEC-DESER-01','JAVA-SEC-CMDI-01']),LanguageBranch('android','Android',focus=['Storage','Crypto'],top_risks=['Weak crypto'],rule_ids=['JAVA-SEC-CRYPTO-01','JAVA-SEC-SECRET-01']),LanguageBranch('enterprise_legacy','Legacy',focus=['OGNL','XXE'],top_risks=['RCE'],rule_ids=['JAVA-STR-01','JAVA-SEC-DESER-01']),LanguageBranch('data_processing','Batch',focus=['Secrets'],top_risks=['Deserialization'],rule_ids=['JAVA-SEC-DESER-01'])]
BEST=[BestPractice('Prepared statements','Use parameters.','PreparedStatement ps;','concat SQL'),BestPractice('Safe deserialization','Prefer JSON.','ObjectMapper','ObjectInputStream')]
LANGUAGE=LanguageModule('java','17+ / 21 LTS',['.java'],'Java security knowledge base','https://docs.oracle.com/en/java/',SECURITY,ENGINEERING,[SPRING,SPRING_SECURITY,HIBERNATE,STRUTS],BRANCHES,BEST)
