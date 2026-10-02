"""Inspect APT source lists/Deb822 and supplied security options without fetching."""
import re
import shlex
from urllib.parse import urlsplit
from .common import InputError, Report, filemap, mapping, string

BYPASS=('trusted','allow-insecure','allow-weak','allow-downgrade-to-insecure')
TIME=('check-valid-until','check-date')
KNOWN={'types','uris','suites','components','signed-by','enabled','architectures','architectures-add','architectures-remove','languages','targets','pdiffs','by-hash','description'}|set(BYPASS)|set(TIME)|{'valid-until-min','valid-until-max','date-max-future'}
GLOBAL_BAD={'Acquire::AllowInsecureRepositories','Acquire::AllowDowngradeToInsecureRepositories','Acquire::AllowWeakRepositories','APT::Get::AllowUnauthenticated','Acquire::https::Verify-Peer','Acquire::https::Verify-Host','Acquire::Check-Valid-Until','Acquire::Check-Date'}
LIMITS=['Static source/trust option policy. No Release signature, keyring ownership/readability, key authenticity, expiry, network result or repository trustworthiness is established.',
 'HTTPS is an explicit transport privacy/integrity policy choice; HTTP alone does not bypass APT signature verification.',
 'Global options completeness is caller asserted. Embedded keys, fingerprint-only global keyring selections and unknown source/global options are OPEN.']

def boolean(value,label):
    if type(value) is bool:return value
    if isinstance(value,str) and value.lower() in ('yes','true','1','on'):return True
    if isinstance(value,str) and value.lower() in ('no','false','0','off'):return False
    raise InputError('invalid boolean '+label)

def deb822(text,path):
    stanzas=[];fields={};last=None;start=1
    def flush():
        nonlocal fields,last
        if fields:stanzas.append((path+':'+str(start),fields))
        fields={};last=None
    for number,raw in enumerate(text.splitlines(),1):
        if raw.startswith('#'):continue
        if not raw.strip():flush();start=number+1;continue
        if raw[0].isspace():
            if last is None:raise InputError('orphan Deb822 continuation')
            fields[last]+='\n'+raw.strip();continue
        match=re.fullmatch(r'([A-Za-z][A-Za-z0-9-]*):\s*(.*)',raw)
        if not match:raise InputError('invalid Deb822 field at '+path+':'+str(number))
        key=match[1].lower()
        if key in fields:raise InputError('duplicate Deb822 field '+key)
        fields[key]=match[2];last=key
    flush();return stanzas

def one_line(text,path):
    rows=[]
    for number,raw in enumerate(text.splitlines(),1):
        line=raw.strip()
        if not line or line.startswith('#'):continue
        match=re.fullmatch(r'(deb|deb-src)\s+(?:\[([^\]]*)\]\s+)?(.*)',line)
        if not match:raise InputError('invalid one-line source at '+path+':'+str(number))
        try:parts=shlex.split(match[3],comments=True);opts=shlex.split(match[2] or '')
        except ValueError as exc:raise InputError(str(exc)) from exc
        if len(parts)<2:raise InputError('source missing URI/suite')
        fields={'types':match[1],'uris':parts[0],'suites':parts[1],'components':' '.join(parts[2:])}
        for option in opts:
            if '=' not in option:raise InputError('source option needs key=value')
            key,value=option.split('=',1);key=key.lower()
            if key in fields:raise InputError('duplicate source option')
            fields[key]=value.replace(',',' ')
        rows.append((path+':'+str(number),fields))
    return rows

def analyze(snapshot):
    mapping(snapshot,'snapshot');files=filemap(snapshot.get('files'));global_=mapping(snapshot.get('global_options',{}),'global_options')
    complete=snapshot.get('global_options_complete',False)
    if type(complete) is not bool:raise InputError('global_options_complete must be boolean')
    report=Report('AptSourceTrustAudit','All supplied active one-line and Deb822 repositories plus supplied security overrides')
    if not complete:report.add('global_coverage','OPEN','global_options','Global configuration completeness not asserted')
    for key,value in global_.items():
        string(key,'global option')
        if key not in GLOBAL_BAD:report.add('global_option','OPEN',key,'Unknown/global option outside policy');continue
        expected=key.endswith(('Verify-Peer','Verify-Host','Check-Valid-Until','Check-Date'))
        report.check('global_override',boolean(value,key)==expected,key,'Global trust/transport/time override')
    rows=[]
    for path,text in files.items():
        if path.endswith('.sources'):rows.extend((where,fields,'deb822') for where,fields in deb822(text,path))
        elif path.endswith('.list'):rows.extend((where,fields,'one-line') for where,fields in one_line(text,path))
        else:report.add('file_scope','OPEN',path,'Unknown source-file format')
    seen={};active=0;expansions=0
    for where,fields,format_ in rows:
        if format_ == 'deb822' and 'enabled' in fields and not boolean(fields['enabled'],'Enabled'):
            report.add('disabled_source','PASS',where,'Disabled stanza, outside active-source scope');continue
        active+=1
        known = KNOWN if format_ == 'deb822' else KNOWN - {'enabled'}
        for key in fields:
            if key not in known:report.add('field','OPEN',where,'Unknown field '+key)
        types=fields.get('types','').split();uris=fields.get('uris','').split();suites=fields.get('suites','').split();components=fields.get('components','').split()
        if not types or not uris or not suites:raise InputError('source needs Types, URIs, Suites')
        if set(types)-{'deb','deb-src'}:raise InputError('unknown package source type')
        expansions+=len(types)*len(uris)*len(suites)*max(1,len(components))
        if expansions>10000:raise InputError('repository expansion budget exceeded')
        for suite in suites:
            if suite.endswith('/') and components:raise InputError('exact-path suite forbids Components')
            if not suite.endswith('/') and not components:raise InputError('distribution suite requires Components')
        for key in BYPASS:
            if key in fields:report.check('trust_bypass',not boolean(fields[key],key),where,key+' authentication override')
        for key in TIME:
            if key in fields:report.check('replay_protection',boolean(fields[key],key),where,key+' expiry/time policy')
        for key in ('valid-until-min','valid-until-max','date-max-future'):
            if key in fields:report.add('time_window','OPEN',where,'Custom expiry/time window requires repository review')
        signing=fields.get('signed-by','')
        if not signing:report.add('key_scope','FAIL',where,'No per-repository signing-key scope')
        elif 'BEGIN PGP PUBLIC KEY BLOCK' in signing:report.add('key_scope','OPEN',where,'Embedded key authenticity/format not verified')
        else:
            paths=signing.split();valid=bool(paths);fingerprints=False
            for token in paths:
                if re.fullmatch(r'[A-Fa-f0-9]{40}!?',token):fingerprints=True;continue
                if not token.startswith('/') or '..' in token.split('/') or token.endswith('/'):
                    valid=False
                elif not token.startswith(('/etc/apt/keyrings/','/usr/share/keyrings/')):report.add('key_location','OPEN',where,'Non-recommended keyring location')
            report.check('key_scope',valid,where,'Absolute scoped keyrings/fingerprints required')
            if fingerprints and not any(t.startswith('/') for t in paths):report.add('key_scope','OPEN',where,'Fingerprint-only selection uses global keyring trust')
        for uri in uris:
            try:parsed=urlsplit(uri);_ = parsed.port
            except ValueError as exc:raise InputError('invalid source URI') from exc
            if parsed.username is not None or parsed.password is not None:report.add('credential_uri','FAIL',where,'Credentials embedded in repository URI')
            if parsed.query or parsed.fragment:report.add('uri_parameters','OPEN',where,'URI query/fragment scope requires review')
            if parsed.scheme in ('http','https'):
                if not parsed.hostname:raise InputError('network repository URI missing host')
                report.check('transport',parsed.scheme=='https',where,'HTTPS transport policy')
            elif parsed.scheme in ('file','cdrom','copy'):report.add('transport','OPEN',where,'Local/removable repository authorization not established')
            else:report.add('transport','OPEN',where,'Unsupported repository transport')
            for suite in suites:
                for type_ in types:
                    key=(type_,uri,suite,tuple(components));policy=tuple(sorted((k,v) for k,v in fields.items() if k not in ('types','uris','suites','components')))
                    if key in seen:report.add('duplicate_source','FAIL',where,'Duplicate or conflicting source identity')
                    seen[key]=policy
    if not active:report.add('coverage','OPEN','files','No active package sources')
    return report.finish(LIMITS)
