import streamlit as st
import json
import os
import re
import time
from html import escape as html_escape
from urllib.parse import urlencode
from SPARQLWrapper import SPARQLWrapper, JSON
from openai import OpenAI
from authlib.integrations.requests_client import OAuth2Session

# --- OIDC Configuration ---
OIDC_ENABLED = bool(os.environ.get("OIDC_AUTHORITY"))
OIDC_AUTHORITY = os.environ.get("OIDC_AUTHORITY", "")
OIDC_CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "")
OIDC_REDIRECT_URI = os.environ.get("OIDC_REDIRECT_URI", "http://localhost:8501")
OIDC_SCOPES = "openid email profile"

# --- LLM API defaults (can be overridden in the UI) ---
DEFAULT_API_BASE_URL = os.environ.get("DEFAULT_API_BASE_URL", "")
DEFAULT_API_MODEL = os.environ.get("DEFAULT_API_MODEL", "gpt-4o-mini")


def get_oidc_session():
    return OAuth2Session(
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        redirect_uri=OIDC_REDIRECT_URI,
        scope=OIDC_SCOPES,
    )


def _get_login_url():
    """Build the Keycloak authorization URL."""
    session = get_oidc_session()
    auth_url = f"{OIDC_AUTHORITY}/protocol/openid-connect/auth"
    uri, _ = session.create_authorization_url(auth_url)
    return uri


def _get_logout_url():
    """Build the Keycloak logout URL."""
    logout_url = f"{OIDC_AUTHORITY}/protocol/openid-connect/logout"
    params = urlencode({"post_logout_redirect_uri": OIDC_REDIRECT_URI, "client_id": OIDC_CLIENT_ID})
    return f"{logout_url}?{params}"


def oidc_login():
    """Redirect the user to Keycloak login."""
    safe_uri = html_escape(_get_login_url(), quote=True)
    st.markdown(f'<meta http-equiv="refresh" content="0;url={safe_uri}">', unsafe_allow_html=True)
    st.stop()


def oidc_handle_callback():
    """Exchange the authorization code for tokens.

    Security note: state/PKCE validation is not possible because Streamlit's
    session state does not survive the browser redirect to Keycloak and back.
    This is safe because we are a *confidential* client — the token exchange
    requires the client secret, which only the server knows.
    """
    code = st.query_params.get("code")
    if not code:
        return False

    # Use internal authority for server-side calls if available, else public
    token_authority = os.environ.get("OIDC_INTERNAL_AUTHORITY", OIDC_AUTHORITY)

    session = get_oidc_session()
    token_url = f"{token_authority}/protocol/openid-connect/token"
    try:
        token = session.fetch_token(
            token_url,
            code=code,
            grant_type="authorization_code",
        )
    except Exception as e:
        st.session_state["oidc_error_detail"] = f"Token exchange failed: {e}"
        return False

    userinfo_url = f"{token_authority}/protocol/openid-connect/userinfo"
    resp = session.get(userinfo_url)
    if resp.status_code == 200:
        userinfo = resp.json()
        st.session_state["user"] = {
            "name": userinfo.get("preferred_username", userinfo.get("sub", "user")),
            "email": userinfo.get("email", ""),
            "full_name": userinfo.get("name", ""),
        }
        st.session_state["oidc_token"] = token
        st.query_params.clear()
        return True
    else:
        st.session_state["oidc_error_detail"] = f"Userinfo failed (status {resp.status_code}): {resp.text}"
        return False


def oidc_logout():
    """Clear session and redirect to Keycloak logout."""
    logout_url = f"{OIDC_AUTHORITY}/protocol/openid-connect/logout"
    params = urlencode({"post_logout_redirect_uri": OIDC_REDIRECT_URI, "client_id": OIDC_CLIENT_ID})
    for key in ["user", "oidc_token", "messages"]:
        st.session_state.pop(key, None)
    safe_url = html_escape(f"{logout_url}?{params}", quote=True)
    st.markdown(f'<meta http-equiv="refresh" content="0;url={safe_url}">', unsafe_allow_html=True)
    st.stop()


def _is_token_expired():
    """Check if the stored OIDC token has expired."""
    token = st.session_state.get("oidc_token")
    if not token:
        return True
    expires_at = token.get("expires_at")
    if not expires_at:
        return True
    return time.time() >= (expires_at - 30)


def _refresh_access_token():
    """Use the refresh token to get a new access token. Returns True on success."""
    token = st.session_state.get("oidc_token")
    if not token or "refresh_token" not in token:
        return False

    token_authority = os.environ.get("OIDC_INTERNAL_AUTHORITY", OIDC_AUTHORITY)
    token_url = f"{token_authority}/protocol/openid-connect/token"

    session = get_oidc_session()
    try:
        new_token = session.fetch_token(
            token_url,
            grant_type="refresh_token",
            refresh_token=token["refresh_token"],
        )
        st.session_state["oidc_token"] = new_token
        return True
    except Exception:
        return False


def require_auth():
    """Enforce OIDC authentication. Returns True if authenticated."""
    if not OIDC_ENABLED:
        return True

    # Handle callback from Keycloak
    if "code" in st.query_params and "user" not in st.session_state:
        if not oidc_handle_callback():
            # Store error so it survives the rerun
            st.session_state["oidc_error"] = True
        st.query_params.clear()
        st.rerun()

    # Clean stale code from URL
    if "code" in st.query_params:
        st.query_params.clear()
        st.rerun()

    # Auto-refresh expired access tokens
    if "user" in st.session_state and _is_token_expired():
        if not _refresh_access_token():
            for key in ["user", "oidc_token"]:
                st.session_state.pop(key, None)

    # Not authenticated
    if "user" not in st.session_state:
        return False

    return True


# --- Rijksoverheid theming ---
RIJKS_DONKERBLAUW = "#154273"
RIJKS_HEMELBLAUW = "#007BC7"
RIJKS_WIT = "#FFFFFF"
RIJKS_LICHTGRIJS = "#F3F3F3"

SPARQL_ENDPOINT = os.environ.get("SPARQL_ENDPOINT", "")

# Schema description for the LLM to generate SPARQL queries
SCHEMA_DESCRIPTION = """
De CODW SPARQL endpoint bevat gevalideerde regelspecificaties van de Nederlandse overheid.

=== PREFIXES ===
PREFIX cpsv:  <http://purl.org/vocab/cpsv#>
PREFIX dct:   <http://purl.org/dc/terms/>
PREFIX m8g:   <http://data.europa.eu/m8g/>
PREFIX skos:  <http://www.w3.org/2004/02/skos/core#>
PREFIX eli:   <http://data.europa.eu/eli/ontology#>
PREFIX rdfs:  <http://www.w3.org/2000/01/rdf-schema#>
PREFIX rdf:   <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX dcat:  <http://www.w3.org/ns/dcat#>
PREFIX cprmv: <https://cprmv.open-regels.nl/0.3.0/>

=== DATAMODEL OVERZICHT ===

De data is hiërarchisch opgebouwd:
  PublicService (dienst) → cpsv:Rule (regels) → cprmv:extends (sub-regels)

BELANGRIJK: Top-level regels zijn SAMENVATTEND — ze noemen alle sub-concepten
in hun beschrijving. De SPECIFIEKE regellogica (beslisbomen, formules, bedragen) zit in de
DIEPERE sub-regels (leaf-regels). Zoek dus bij specifieke vragen op regel-niveau.

=== KLASSEN ===

1. cpsv:PublicService — publieke diensten (13 stuks)
   Properties: dct:title, dct:description, dct:identifier, dcat:keyword,
   m8g:hasCompetentAuthority, m8g:hasLegalResource, cprmv:hasDecisionModel

2. cpsv:Rule — regels die bij een dienst horen (~298 stuks, KERN VAN DE DATA)
   Properties:
   - dct:title — titel van de regel
   - dct:description — BEVAT DE WERKELIJKE REGELLOGICA: beslisbomen, formules, voorwaarden, bedragen
   - dct:identifier — code (bijv. "B03.02", "BASVO004.01")
   - cpsv:implements → PublicService URI (koppelt regel aan dienst)
   - cprmv:extends → cpsv:Rule URI (koppelt sub-regel aan parent-regel)
   - cprmv:confidenceLevel — "high" of "medium"
   - cprmv:validFrom — ingangsdatum

   Sub-types:
   a) cprmv:TemporalRule — business rules met dct:description (beslislogica in tekst)
   b) cprmv:DecisionRule — DMN decision table rijen (met cprmv:decisionTable, cprmv:ruleType)

3. cprmv:Rule — regels afgeleid uit wettekst, met:
   - cprmv:situatie — situatiebeschrijving uit de wet
   - cprmv:norm — normwaarde (bijv. "2.200", "1.001,07")
   - cprmv:definition — volledige wettekstpassage

4. m8g:PublicOrganisation — overheidsorganisaties
   - skos:prefLabel — naam

5. cpsv:Input / cpsv:Output — invoer/uitvoer van DMN-modellen
   - dct:identifier, dct:title, dct:type, schema:value

6. eli:LegalResource — wettelijke bronnen
7. skos:Concept / skos:ConceptScheme — begrippen/vocabulaires

=== RELATIES TUSSEN REGELS ===

- cpsv:implements — regel → dienst (elke regel wijst naar zijn dienst)
- cprmv:extends — sub-regel → parent-regel (hiërarchie)
  Regel ZONDER cprmv:extends = top-level regel (samenvattend)
  Regel die NIET door anderen ge-extend wordt = leaf-regel (meest specifiek)

=== ORGANISATIES ===
- Dienst Uitvoering Onderwijs (DUO) — studiefinanciering
- Onderwijs, Cultuur en Wetenschap (OCW) — basisbekostiging VO
- Rijksdienst voor Ondernemend Nederland (RVO) — ISDE subsidie dakisolatie
- Sociale Verzekeringsbank (SVB) — AOW
- Uitvoeringsinstituut Werknemersverzekeringen (UWV) — WW, AOW
- Directoraat-generaal Toeslagen — zorgtoeslag
- Gemeente Heusden — heusdenpas kindpakket
- Provincie Flevoland — vergunningen, bomen, HR onboarding
- Sociale Zaken en Werkgelegenheid (SZW) — normbedragen bijstand

=== ALLE PUBLIEKE DIENSTEN MET HUN REGELBOMEN ===

1. studiefinanciering (DUO) — 27 regels
   B01.01 Besluit aanvraag studiefinanciering (TOP)
   ├─ B02.01 Persoon heeft aanspraak
   │  ├─ B02.02 Leeftijd (beslisboom: 18-30, HO, ononderbroken)
   │  │  └─ B02.02.02 Ononderbroken inschrijving
   │  ├─ B02.03 Nationaliteitsvoorwaarden
   │  │  └─ B02.03.02 EU voorwaarden
   │  └─ B02.04 Correcte opleiding
   ├─ B03.01 Totaalbedrag (A + B + C)
   │  ├─ B03.02 Basisbeurs (beslisboom: uit/thuiswonend × MBO/HO → bedragen)
   │  ├─ B03.03 Aanvullende beurs (Max(A-B, 0))
   │  │  ├─ B03.03.01 Maximaal aanvullend
   │  │  └─ B03.03.02 Maandelijkse inhouding
   │  │     └─ B03.03.03 Totaalbedrag per kind
   │  │        └─ B03.03.04 Rekeninkomen ouders
   │  │           └─ B03.03.05 Jaarbedrag per ouder (A - B - C)
   │  │              ├─ B03.03.06 Aftrekpost andere kinderen
   │  │              └─ B03.03.07 Rekeninkomen van een ouder (C × (A - B))
   │  │                 ├─ B03.03.08 Vrijgesteld bedrag van de ouder
   │  │                 └─ B03.03.09 Percentage meetellend inkomen
   │  └─ B03.04 Bedrag aan lening
   B03.04.01 Persoon is uitwonend (los)
   B03.05 Het maximale leenbedrag (los)
   └─ B03.06 Maximale lening
   B04.01 Persoon heeft nog tenminste één maand studiefinanciering
   ├─ B04.02 Verbruikte jaren
   │  └─ B04.04 Aantal jaar voor een inschrijving
   └─ B04.05 Opnametermijn

2. basisbekosting-vo (OCW) — 13 regels — basisbekostiging voortgezet onderwijs
   BASVO001.01 Onderwijsinstelling komt in aanmerking voor Basisbekostiging VO 2025 (TOP)
   └─ BASVO003.02 Eindbedrag basisbekostiging VO (A + B)
      ├─ BASVO004.01 Bekostiging leerlingen (A + B)
      │  ├─ BASVO004.02 Bekostiging leerlingen PRO en bovenbouw VBO bb/kb
      │  │  └─ BASVO002.06 Bedrag leerlingen PRO/VBO 2025 (€ 11.185,30/leerling)
      │  └─ BASVO004.03 Bekostiging leerlingen VWO/HAVO/MAVO/VBO excl bb/kb
      │     └─ BASVO002.05 Bedrag leerlingen VWO/HAVO 2025 (€ 9.507,49/leerling)
      └─ BASVO005.03 Vast bedrag van toepassing op vestiging (beslisboom)
         ├─ BASVO002.03 Vast bedrag hoofdvestiging 2025 (€ 275.595,52)
         ├─ BASVO002.04 Vast bedrag nevenvestiging 2025 (€ 137.797,76)
         └─ BASVO005.04 Vestiging voldoet aan minimumeis leerlingen (beslisboom)
            ├─ BASVO005.09 Minimum leerlingen niet-PRO (≥ 130)
            └─ BASVO005.10 Minimum leerlingen uitsluitend PRO (≥ 60)

3. isde-subsidie-dakisolatie (RVO) — 13 regels — ISDE subsidie voor dakisolatie
   ISDE001.01 Aanvraag dakisolatie komt in aanmerking (TOP)
   └─ ISDE002.01 Bereken ISDE-subsidie dakisolatie
      ├─ ISDE003.01 Berekening R-waardewinst (ΔR)
      ├─ ISDE003.02 Berekening extra isolatiedikte (mm)
      ├─ ISDE003.03 Berekening materiaalkosten (€)
      ├─ ISDE003.04 Berekening installatiekosten (€)
      ├─ ISDE003.05 Berekening totale kosten (€)
      ├─ ISDE003.06 Berekening netto kosten na subsidie (€)
      ├─ ISDE003.07 Berekening terugverdientijd (jaar)
      ├─ ISDE004.01 Subsidiescenario R=3,0
      ├─ ISDE004.02 Subsidiescenario R=4,0
      ├─ ISDE004.03 Subsidiescenario R=6,0 (aanbevolen)
      └─ ISDE004.04 Subsidiescenario R=8,0

4. zorgtoeslag-lvnsgb (Toeslagen) — 12 regels — GEEN hiërarchie (alle top-level)
   Regelgroep 001: Hoogte toeslag bij ontbrekende draagkracht
   Regelgroep 002: Hoogte toeslag (alleenstaand)
   Regelgroep 003: Inkomen boven drempel
   Regelgroep 004: Standaardpremie
   Regelgroep 005: Woonlandfactor
   Regelgroep 006: Datum berekening
   Regelgroep 007: Leeftijd
   Regelgroep 008: In leven
   Regelgroep 010: Recht op zorgtoeslag
   Regelgroep 011: Recht op zorgtoeslag verzekerde zonder partner
   Regelgroep 012: Rechtgevende leeftijd
   Regelgroep 013: Motivaties recht op zorgtoeslag

5. hr-onboarding (Flevoland) — 11 regels — GEEN hiërarchie (alle top-level)
   Rule_01–Rule_11: Rol-toewijzingsregels per functie
   (caseworker, senior-behandelaar, RIP-verkenner, planner, inkoop, etc.)

6. tree-felling (Flevoland) — 1 regel: Tree diameter
7. replacement-tree (Flevoland) — 1 regel: Replacement tree diameter
8. rip-assignment (Flevoland) — via DMN DecisionRules
9. aow-leeftijd (SVB) — via DMN inputs/outputs
10. aow-leeftijd-uwv (UWV) — via DMN inputs/outputs
11. ww-uitkering (UWV) — via DMN DecisionRules
12. heusdenpaskindpakket (Gemeente Heusden) — via DMN DecisionRules
13. normbedragen (SZW) — bijstandsnormen, via DMN DecisionRules + cprmv:Rule (wettekst)
"""

NL2SPARQL_SYSTEM = f"""Je bent een SPARQL-query generator voor de CODW-dataset (Nederlandse overheidsregelspecificaties).

Je taak: genereer een SPARQL SELECT query die de juiste data ophaalt voor de gebruikersvraag.

{SCHEMA_DESCRIPTION}

=== QUERY STRATEGIE ===

STAP 1: Bepaal het juiste query-niveau.
- Overzichtsvraag ("welke diensten?") → query op cpsv:PublicService
- Regelvraag ("welke regels voor X?") → query op cpsv:Rule met cpsv:implements filter
- Specifieke vraag ("hoe wordt Y berekend?") → zoek in dct:description van cpsv:Rule

STAP 2: Bepaal de juiste dienst. Gebruik de regelbomen hierboven om de vraag te mappen:
- "bekostiging", "VO", "leerlingen", "vestiging" → basisbekosting-vo (OCW)
- "studie", "beurs", "lening", "studiefinanciering" → studiefinanciering (DUO)
- "isolatie", "dak", "R-waarde", "ISDE" → isde-subsidie-dakisolatie (RVO)
- "zorgtoeslag", "standaardpremie", "draagkracht" → zorgtoeslag-lvnsgb
- "AOW", "pensioen" → aow-leeftijd / aow-leeftijd-uwv
- "WW", "werkloosheid" → ww-uitkering
- "bijstand", "normbedrag" → normbedragen (SZW)
- "boom", "kappen", "kapvergunning" → tree-felling / replacement-tree
- "onboarding", "functie", "rol" → hr-onboarding
- "heusdenpas", "kindpakket" → heusdenpaskindpakket

STAP 3: Zoek op het juiste NIVEAU in de hiërarchie.
- Top-level regels zijn SAMENVATTEND
- Leaf-regels (zonder kinderen) bevatten de SPECIFIEKE LOGICA
- Voor specifieke vragen: gebruik FILTER NOT EXISTS {{ ?child cprmv:extends ?rule }}

REGELS:
1. Genereer ALLEEN een SPARQL query, geen uitleg.
2. Wrap de query in ```sparql ... ``` codeblok.
3. Gebruik altijd de juiste prefixes.
4. Vraag NIET beantwoordbaar → antwoord EXACT met: NO_DATA
5. Dataset bevat ALLEEN regelspecificaties Nederlandse overheidsdiensten → andere onderwerpen → NO_DATA.

ZOEK-REGELS:
6. Zoek altijd breed met FILTER over MEERDERE velden:
   FILTER(
     CONTAINS(LCASE(STR(?title)), "zoekterm") ||
     CONTAINS(LCASE(STR(?description)), "zoekterm") ||
     CONTAINS(LCASE(STR(?id)), "zoekterm")
   )
   Gebruik korte woordstammen als zoekterm (bijv. "bekostig" i.p.v. "basisbekostiging").

7. Haal altijd op: dct:identifier, dct:title, dct:description, en parent-info via cprmv:extends.
8. Gebruik OPTIONAL voor optionele properties (description, extends, etc.).
9. LIMIT resultaten tot 50.

VOORBEELD — specifieke leaf-regels zoeken:
```sparql
PREFIX cpsv: <http://purl.org/vocab/cpsv#>
PREFIX dct: <http://purl.org/dc/terms/>
PREFIX cprmv: <https://cprmv.open-regels.nl/0.3.0/>

SELECT ?rule ?id ?title ?description ?parentTitle ?serviceName WHERE {{
  ?rule a cpsv:Rule ;
        dct:identifier ?id ;
        dct:title ?title ;
        cpsv:implements ?service .
  ?service dct:title ?serviceName .
  OPTIONAL {{ ?rule dct:description ?description }}
  OPTIONAL {{ ?rule cprmv:extends ?parent . ?parent dct:title ?parentTitle }}
  FILTER(
    CONTAINS(LCASE(STR(?title)), "bekostig") ||
    CONTAINS(LCASE(STR(?description)), "bekostig")
  )
}}
LIMIT 50
```

VOORBEELD — alle regels van een specifieke dienst:
```sparql
PREFIX cpsv: <http://purl.org/vocab/cpsv#>
PREFIX dct: <http://purl.org/dc/terms/>
PREFIX cprmv: <https://cprmv.open-regels.nl/0.3.0/>

SELECT ?rule ?id ?title ?description ?parentId ?parentTitle WHERE {{
  ?rule a cpsv:Rule ;
        dct:identifier ?id ;
        dct:title ?title ;
        cpsv:implements ?service .
  ?service dct:identifier "basisbekosting-vo" .
  OPTIONAL {{ ?rule dct:description ?description }}
  OPTIONAL {{
    ?rule cprmv:extends ?parent .
    ?parent dct:identifier ?parentId ;
           dct:title ?parentTitle .
  }}
}}
ORDER BY ?id
LIMIT 50
```
"""


st.set_page_config(
    page_title="Open Regels – CODW",
    page_icon="🏛️",
    layout="wide",
)

st.markdown(f"""
<style>
    /* Make the default Streamlit header transparent so the sidebar toggle remains visible */
    header[data-testid="stHeader"] {{
        background: transparent !important;
    }}
    /* Remove default top padding to let the banner sit at the top */
    .stMainBlockContainer {{
        padding-top: 0 !important;
    }}
    section[data-testid="stSidebar"] {{
        background-color: {RIJKS_DONKERBLAUW};
    }}
    section[data-testid="stSidebar"] * {{
        color: {RIJKS_WIT} !important;
    }}
    section[data-testid="stSidebar"] input {{
        color: #000 !important;
        background-color: {RIJKS_WIT} !important;
    }}
    section[data-testid="stSidebar"] .stTextInput label,
    section[data-testid="stSidebar"] .stSelectbox label {{
        color: {RIJKS_WIT} !important;
    }}
    .stButton > button {{
        background-color: {RIJKS_HEMELBLAUW};
        color: {RIJKS_WIT};
        border: none;
        border-radius: 4px;
    }}
    .stButton > button:hover {{
        background-color: {RIJKS_DONKERBLAUW};
        color: {RIJKS_WIT};
    }}
    .stChatMessage {{
        border-left: 4px solid {RIJKS_HEMELBLAUW};
    }}
    /* Single navbar */
    .rijks-navbar {{
        background-color: {RIJKS_DONKERBLAUW};
        color: {RIJKS_WIT};
        padding: 0.8rem 1.5rem;
        margin: -1rem -1rem 1.5rem -1rem;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }}
    .rijks-navbar h1 {{
        color: {RIJKS_WIT};
        font-size: 1.4rem;
        margin: 0;
        font-family: 'RO Sans', 'Rijksoverheid Sans', sans-serif;
    }}
    .rijks-navbar .subtitle {{
        color: #B2D4EC;
        font-size: 0.85rem;
    }}
    .rijks-navbar .navbar-auth {{
        display: flex;
        align-items: center;
        gap: 0.8rem;
        white-space: nowrap;
    }}
    .rijks-navbar .navbar-user {{
        color: {RIJKS_WIT};
        font-size: 0.9rem;
        font-weight: 600;
    }}
    .rijks-navbar .navbar-btn {{
        background-color: {RIJKS_HEMELBLAUW};
        color: {RIJKS_WIT};
        border: none;
        border-radius: 4px;
        padding: 0.4rem 1rem;
        font-size: 0.85rem;
        cursor: pointer;
        text-decoration: none;
        font-weight: 600;
    }}
    .rijks-navbar .navbar-btn:hover {{
        background-color: #005A9C;
    }}
    .source-box {{
        background-color: {RIJKS_LICHTGRIJS};
        border-left: 3px solid {RIJKS_HEMELBLAUW};
        padding: 0.5rem 0.8rem;
        margin: 0.3rem 0;
        font-size: 0.85rem;
        border-radius: 2px;
    }}
    .sparql-box {{
        background-color: #1e1e1e;
        color: #d4d4d4;
        padding: 0.8rem;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.8rem;
        white-space: pre-wrap;
        overflow-x: auto;
    }}
</style>
""", unsafe_allow_html=True)

authenticated = require_auth()

# --- Single navbar with integrated auth ---
if OIDC_ENABLED and authenticated:
    user = st.session_state["user"]
    logout_url = html_escape(_get_logout_url(), quote=True)
    auth_html = (
        f'<div class="navbar-auth">'
        f'<span class="navbar-user">{html_escape(user["name"])}</span>'
        f'<a class="navbar-btn" href="{logout_url}" target="_self">Uitloggen</a>'
        f'</div>'
    )
elif OIDC_ENABLED:
    login_url = html_escape(_get_login_url(), quote=True)
    auth_html = (
        f'<div class="navbar-auth">'
        f'<a class="navbar-btn" href="{login_url}" target="_self">Inloggen</a>'
        f'</div>'
    )
else:
    auth_html = ''

st.markdown(f"""
<div class="rijks-navbar">
    <div>
        <h1>Open Regels — CODW</h1>
        <div class="subtitle">Regelspecificaties van de Nederlandse overheid</div>
    </div>
    {auth_html}
</div>
""", unsafe_allow_html=True)

if OIDC_ENABLED and not authenticated:
    if st.session_state.pop("oidc_error", False):
        detail = st.session_state.pop("oidc_error_detail", "")
        st.error(f"Inloggen mislukt. {detail}" if detail else "Inloggen mislukt. Probeer opnieuw.")
    st.info("Je moet inloggen om deze applicatie te gebruiken.")
    st.stop()

# --- Sidebar ---
with st.sidebar:
    st.markdown("### ⚙️ API-configuratie")
    base_url = st.text_input("OpenAI-compatible Base URL", value=DEFAULT_API_BASE_URL, placeholder="https://api.openai.com/v1")
    api_key = st.text_input("API Key", type="password", placeholder="sk-...")
    model_name = st.text_input("Model", value=DEFAULT_API_MODEL, placeholder="model name")
    st.markdown("---")
    show_sparql = st.checkbox("Toon gegenereerde SPARQL query", value=True)
    st.markdown("---")
    st.markdown("### ℹ️ Over deze app")
    st.markdown(
        "Deze app vertaalt je vraag naar een **SPARQL query**, "
        "voert die uit op de CODW-dataset, "
        "en geeft een antwoord op basis van de resultaten. "
        "Als de dataset geen relevante data bevat, wordt dat eerlijk gemeld."
    )


# --- SPARQL execution ---
def run_sparql(query: str) -> tuple[list[dict], str | None]:
    """Execute SPARQL query. Returns (results, error)."""
    try:
        sparql = SPARQLWrapper(SPARQL_ENDPOINT)
        sparql.setReturnFormat(JSON)
        sparql.setQuery(query)
        results = sparql.query().convert()
        return results["results"]["bindings"], None
    except Exception as e:
        return [], str(e)


def extract_sparql(llm_response: str) -> str | None:
    """Extract SPARQL query from LLM response."""
    match = re.search(r"```sparql\s*(.*?)\s*```", llm_response, re.DOTALL)
    if match:
        return match.group(1).strip()
    # Fallback: try to find a SELECT query directly
    match = re.search(r"(PREFIX.*?SELECT.*)", llm_response, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def format_sparql_results(bindings: list[dict]) -> str:
    """Format SPARQL results as readable text for the LLM."""
    if not bindings:
        return "Geen resultaten gevonden."

    parts = []
    for i, row in enumerate(bindings, 1):
        fields = []
        for key, val in row.items():
            v = val.get("value", "")
            fields.append(f"  {key}: {v}")
        parts.append(f"[{i}]\n" + "\n".join(fields))
    return "\n\n".join(parts)


def extract_sources(bindings: list[dict]) -> list[dict]:
    """Extract displayable sources from SPARQL results."""
    sources = []
    seen = set()
    for row in bindings:
        # Try to find a URI and a title
        uri = None
        title = None
        org = None
        for key, val in row.items():
            v = val.get("value", "")
            t = val.get("type", "")
            if t == "uri" and not uri and "triply" not in v and "w3.org" not in v and "purl.org" not in v and "europa.eu" not in v:
                uri = v
            if "title" in key.lower() or "name" in key.lower() or "label" in key.lower():
                if not title:
                    title = v
            if "org" in key.lower():
                org = v

        if uri and uri not in seen:
            seen.add(uri)
            sources.append({"title": title or uri.split("/")[-1], "uri": uri, "org": org or ""})

    return sources


# --- Chat ---
if "messages" not in st.session_state:
    st.session_state.messages = []

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"], unsafe_allow_html=True)

if prompt := st.chat_input("Stel een vraag over Nederlandse regelgeving..."):
    if not base_url or not api_key:
        st.error("Vul eerst de API Base URL en API Key in via de zijbalk.")
        st.stop()

    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    client = OpenAI(base_url=base_url, api_key=api_key)

    # --- Step 1: NL → SPARQL ---
    with st.chat_message("assistant"):
        with st.spinner("🔍 SPARQL query genereren..."):
            try:
                nl2sparql_response = client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": NL2SPARQL_SYSTEM},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.1,
                    max_tokens=1024,
                )
                sparql_raw = nl2sparql_response.choices[0].message.content
            except Exception as e:
                st.error(f"API-fout bij query generatie: {e}")
                st.stop()

        # Check if LLM says NO_DATA
        if "NO_DATA" in sparql_raw:
            answer = (
                "Helaas kan ik deze vraag niet beantwoorden op basis van de CODW-dataset. "
                "De dataset bevat alleen regelspecificaties van Nederlandse overheidsdiensten, "
                "zoals studiefinanciering, zorgtoeslag, WW-uitkering, AOW, subsidies en vergunningen. "
                "Stel gerust een vraag over een van deze onderwerpen."
            )
            st.markdown(answer)
            st.session_state.messages.append({"role": "assistant", "content": answer})
            st.stop()

        # Extract SPARQL
        sparql_query = extract_sparql(sparql_raw)
        if not sparql_query:
            answer = (
                "Er kon geen geldige SPARQL query worden gegenereerd voor deze vraag. "
                "Probeer je vraag specifieker te formuleren over Nederlandse overheidsdiensten of regelgeving."
            )
            st.markdown(answer)
            st.session_state.messages.append({"role": "assistant", "content": answer})
            st.stop()

        if show_sparql:
            with st.expander("🔎 Gegenereerde SPARQL query", expanded=False):
                st.code(sparql_query, language="sparql")

        # --- Step 2: Execute SPARQL ---
        with st.spinner("📡 Query uitvoeren op CODW endpoint..."):
            bindings, error = run_sparql(sparql_query)

        if error:
            # Try once more with a fix prompt
            with st.spinner("🔧 Query herstellen..."):
                try:
                    fix_response = client.chat.completions.create(
                        model=model_name,
                        messages=[
                            {"role": "system", "content": NL2SPARQL_SYSTEM},
                            {"role": "user", "content": prompt},
                            {"role": "assistant", "content": sparql_raw},
                            {"role": "user", "content": f"De query gaf een fout: {error}\nHerstel de query."},
                        ],
                        temperature=0.1,
                        max_tokens=1024,
                    )
                    sparql_raw2 = fix_response.choices[0].message.content
                    sparql_query2 = extract_sparql(sparql_raw2)
                    if sparql_query2:
                        sparql_query = sparql_query2
                        bindings, error = run_sparql(sparql_query)
                        if show_sparql:
                            with st.expander("🔧 Herstelde SPARQL query", expanded=False):
                                st.code(sparql_query, language="sparql")
                except Exception:
                    pass

        if error:
            answer = f"De SPARQL query kon niet worden uitgevoerd. Fout: {error}"
            st.markdown(answer)
            st.session_state.messages.append({"role": "assistant", "content": answer})
            st.stop()

        if not bindings:
            answer = (
                "De SPARQL query leverde geen resultaten op. "
                "Dit betekent dat de CODW-dataset geen informatie bevat over dit specifieke onderwerp. "
                "De dataset bevat regelspecificaties over o.a. studiefinanciering (DUO), zorgtoeslag, "
                "WW-uitkering (UWV), AOW (SVB), subsidies (RVO) en gemeentelijke regelingen."
            )
            st.markdown(answer)
            if show_sparql:
                with st.expander("📊 Query details"):
                    st.code(sparql_query, language="sparql")
                    st.info("0 resultaten")
            st.session_state.messages.append({"role": "assistant", "content": answer})
            st.stop()

        # --- Step 3: Generate answer from results ---
        context = format_sparql_results(bindings)
        sources = extract_sources(bindings)

        answer_system = f"""Je bent een deskundige assistent voor Nederlandse regelgeving en publieke diensten.
Beantwoord de vraag van de gebruiker UITSLUITEND op basis van de onderstaande SPARQL-resultaten uit de CODW-dataset.

Als de resultaten geen relevant antwoord bevatten, zeg dat eerlijk.
Verwijs naar specifieke diensten, organisaties en URI's uit de resultaten.
Antwoord in het Nederlands tenzij de gebruiker in een andere taal schrijft.
Wees concreet en informatief.

SPARQL-RESULTATEN ({len(bindings)} rijen):
{context}"""

        with st.spinner("💬 Antwoord genereren..."):
            try:
                chat_messages = [{"role": "system", "content": answer_system}]
                # Include recent history for follow-up questions
                for msg in st.session_state.messages[-4:]:
                    chat_messages.append({"role": msg["role"], "content": msg["content"]})

                answer_response = client.chat.completions.create(
                    model=model_name,
                    messages=chat_messages,
                    temperature=0.3,
                    max_tokens=2048,
                )
                answer = answer_response.choices[0].message.content
            except Exception as e:
                answer = f"Fout bij het genereren van het antwoord: {e}"

        st.markdown(answer)

        # Show sources
        if sources:
            with st.expander(f"📎 Bronnen ({len(sources)} resultaten uit CODW)"):
                for src in sources:
                    org_str = f" · {src['org']}" if src["org"] else ""
                    st.markdown(
                        f'<div class="source-box">'
                        f'<strong>{src["title"]}</strong>{org_str}<br/>'
                        f'<a href="{src["uri"]}" target="_blank">{src["uri"]}</a>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

        # Show raw results count
        if show_sparql:
            with st.expander(f"📊 Ruwe SPARQL resultaten ({len(bindings)} rijen)"):
                for i, row in enumerate(bindings[:20], 1):
                    cols = {k: v["value"] for k, v in row.items()}
                    st.json(cols)
                if len(bindings) > 20:
                    st.info(f"... en nog {len(bindings) - 20} rijen meer")

        st.session_state.messages.append({"role": "assistant", "content": answer})
