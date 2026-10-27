# CLAUDE.md

Passpoint (Hotspot 2.0 / 802.11u) profile generator for Android and Apple (iOS/iPadOS/macOS). An interactive CLI collects network and credential details, renders profiles with Jinja2, and a FastAPI server delivers them to devices in the format each OS expects for one-tap install. Forked from `omenoen/android_passpoint`; this fork added iOS support (commit `bad7977`).

## Commands

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py                                       # interactive menu: instructions / generate / serve / exit
python -m uvicorn --host 0.0.0.0 restapi:app         # server only, port 8000; Swagger UI at /docs
```

There are no tests, no linter config and no CI. **Always run from the repo root.** Every file path in the code is relative (`profiles/…`, `certificates/…`).

## Layout

| Path | Role |
|---|---|
| `main.py` | CLI wizard (`main`, `profile_generator`), rendering functions (`create_profile`, `create_ios_profile`, `_render_ios_template`, `_cert_to_b64_der`), `start_uvicorn` |
| `restapi.py` | FastAPI `app`: delivery endpoints plus endpoints that create profiles |
| `schema/profile.py` | Pydantic **v1** models (`Profile` → `HomeSP` + `Credential`) used as REST request bodies |
| `schema/profile.json` | JSON Schema for the same shape. Documentation only; nothing loads it |
| `templates/profile_template.py` | `PROFILE_TEMPLATE`: Jinja2 string for the Android PerProviderSubscription MO XML (`urn:wfa:mo:hotspot2dot0-perprovidersubscription:1.0`, SyncML DDF 1.2) |
| `templates/ios_profile_template.py` | `IOS_PROFILE_TEMPLATE`: Jinja2 string for an Apple `.mobileconfig` plist (`com.apple.wifi.managed` payload, plus an optional `com.apple.security.root` CA payload) |
| `templates/multipart_mixed_template.py` | `BASIC_DOCUMENT_BODY`: a `str.format` template (not Jinja) for the Android MIME envelope |
| `profiles/` | Generated output (`<name>.xml`, `<name>.mobileconfig`). The server reads from here |
| `certificates/` | The RADIUS server CA certificate(s) (`*.cer`, PEM or DER) supplied by the operator |

`templates/__init__.py` imports only `profile_template`; the other templates are imported by full module path. `main` and `restapi` import each other. This works because each side uses the other only inside functions. Keep it that way, and don't add module-level use of either from the other.

## Data model

A profile is a nested dict, or a Pydantic object, whose keys match the Passpoint MO node names:

```
HomeSP:     FriendlyName, FQDN, RoamingConsortiumOI?
Credential: Realm + exactly one of
            UsernamePassword { Username, Password, EAPMethod { EAPType, InnerMethod } }
            DigitalCertificate { CertificateType, CertSHA256Fingerprint }
            SIM { IMSI, EAPType }
```

Templates branch on `{% if X is defined %}`. That works only when absent keys are **missing**. It does not work when they are present with the value `None` (see Known bugs).

## How each platform is delivered

**Android:** `GET /passpoint.config?profile=<x.xml>&certificate=<ca.cer>`
1. The profile XML (with the password already base64-encoded inside it by the `b64encode` Jinja filter, as the MO spec requires) is base64-encoded.
2. The CA cert file bytes are base64-encoded as they are.
3. Both go into a `multipart/mixed` body (`application/x-passpoint-profile` + `application/x-x509-ca-cert`) with the fixed `BOUNDARY`.
4. The whole envelope is base64-encoded **again** and served as `Content-Type: application/x-wifi-config`. Chrome on Android hands this to the system installer. Any mistake produces only a generic error on the device.

**Apple:** `GET /passpoint.mobileconfig?profile=<x.mobileconfig>` serves a pre-rendered file as `application/x-apple-aspen-config` and must be opened in Safari. The CA cert is embedded in the plist at generation time (converted to DER base64 by `_cert_to_b64_der`), so no certificate parameter is needed. `Credential.Realm` is written as a single-entry `NAIRealmNames` array (Android carries it as `Credential/Realm` in the MO XML). Payload identifier defaults to the reversed FQDN + `.passpoint`. `TLSTrustedServerNames` defaults to the FQDN; it should be the CN of the RADIUS server cert. UUIDs are regenerated on every render. The profile is unsigned, so iOS shows it as "Unverified".

**Other endpoints:** `POST /profiles/{file_name}` (Android), `POST /profiles/ios/{file_name}?tls_server_name=&payload_identifier=` (iOS), `GET /profiles` (directory listing).

## Known bugs (verified)

Fix these deliberately; don't work around them silently.

1. **REST-created profiles are malformed.** Pydantic v1 sets unset `Optional` fields to `None`, and `None` passes `is defined`. As a result:
   - `POST /profiles/{name}` emits empty `DigitalCertificate`/`SIM`/`RoamingConsortiumOI` nodes next to the real credential.
   - `POST /profiles/ios/{name}` emits `<string>None</string>` for RCOI.
   - The iOS endpoint always emits a `PayloadCertificateAnchorUUID` and a `com.apple.security.root` payload containing `None`, because `ca_cert_uuid`/`ca_cert_b64` are passed explicitly as `None`. It also never accepts a CA cert.
   - The if/elif in the iOS template always takes the `UsernamePassword` branch.

   Fix: use `profile.dict(exclude_none=True)` and test the template values for truthiness or `is not none`. The CLI path builds dicts with missing keys, so it renders correctly.
2. `templates/profile_template.py`: the `CertSHA256Fingerprint` node renders `CertificateType` instead of the fingerprint.
3. `main.profile_generator` SIM branch stores the EAP type under the key `'Username'` instead of `'EAPType'`, so the SIM EAPType node comes out empty.
4. `main.build_ios_mobileconfig` is dead code (its docstring wrongly says the endpoint uses it). It is also broken: the MO XML has a default namespace (`syncml:dmddf1.2`), so `root.iter('Node')` matches nothing. Every lookup returns `None`, and the function crashes at `b64decode(None)`.
5. The iOS `TTLSInnerAuthentication` value is copied verbatim from the Android `InnerMethod` (e.g. `MS-CHAP-V2`). Apple expects `PAP`/`CHAP`/`MSCHAP`/`MSCHAPv2`/`EAP`, so Android-style values need mapping.
6. `start_uvicorn` refuses to start without a `.xml` profile, which blocks iOS-only use. Its docstring says port 80, but the server actually runs on 8000.
7. Android delivery calls `.encode('ascii')` on the XML, so a non-ASCII `FriendlyName` raises an error.
8. REST handlers catch only `fastapi.exceptions.FastAPIError`, so file and render errors surface as 500s.

## Security notes

- The server binds `0.0.0.0` over plain HTTP with no auth, and profiles contain credentials. Use it only on a trusted network for provisioning.
- The `profile`/`certificate` query params are concatenated straight into paths (`'profiles/' + profile`), so path traversal (`../`) can read arbitrary files. The POST endpoints write files under attacker-chosen names. Sanitize with `os.path.basename` or check that the resolved path stays inside the folder before exposing the server more widely.
- There is **no `.gitignore`**. `profiles/*.xml|*.mobileconfig`, `certificates/*.cer`, `.venv/`, `.idea/` and `__pycache__/` are currently untracked and must not be committed. Generated profiles contain plaintext (iOS) or base64 (Android) passwords.

## Conventions

- Python 3.11+ (README targets 3.12; local `.venv` is 3.11). Dependencies are pinned: `pydantic~=1.10` (v1 API: `.dict()`, implicit `Optional = None`), `fastapi~=0.95`, `jinja2~=3.0`, `uvicorn~=0.22`, `cryptography~=41`. Don't use pydantic v2 APIs.
- Templates are Python string constants, not `.j2` files. The Android renderer uses a `jinja2.Environment` that registers the `b64encode` filter. The iOS renderer uses a bare `jinja2.Template`. Neither autoescapes, so XML-special characters in user input (`&`, `<`) produce invalid XML or plist output.
- Field names stay PascalCase to mirror the Passpoint MO node names. Keep `schema/profile.py`, `schema/profile.json`, both templates and the CLI prompts in sync when adding fields.
- EAP type numbers: TTLS 21, TLS 13, SIM 18, AKA 23, AKA' 50.
