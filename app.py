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


def oidc_login():
    """Redirect the user to Keycloak login."""
    session = get_oidc_session()
    auth_url = f"{OIDC_AUTHORITY}/protocol/openid-connect/auth"
    uri, _ = session.create_authorization_url(auth_url)
    safe_uri = html_escape(uri, quote=True)
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

    # Expire session if access token has expired
    if "user" in st.session_state and _is_token_expired():
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
PREFIX cpsv: <http://purl.org/vocab/cpsv#>
PREFIX dct:  <http://purl.org/dc/terms/>
PREFIX m8g:  <http://data.europa.eu/m8g/>
PREFIX skos: <http://www.w3.org/2004/02/skos/core#>
PREFIX eli:  <http://data.europa.eu/eli/ontology#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX dcat: <http://www.w3.org/ns/dcat#>
PREFIX cprmv: <https://cprmv.open-regels.nl/0.3.0/>

=== KLASSEN (rdf:type) ===
- cpsv:PublicService — publieke diensten (13 stuks)
- cpsv:Rule — regels die bij een dienst horen
- cpsv:Input — invoergegevens voor een dienst
- cpsv:Output — resultaat/output van een dienst
- m8g:PublicOrganisation — overheidsorganisaties
- eli:LegalResource — wettelijke bronnen
- m8g:Cost — kosten
- skos:Concept / skos:ConceptScheme — begrippen

=== PROPERTIES VAN cpsv:PublicService ===
- dct:title — titel (LET OP: kan typos bevatten!)
- dct:description — beschrijving (vaak uitgebreider en betrouwbaarder dan de titel)
- dct:identifier — identifier string (bijv. "studiefinanciering", "zorgtoeslag-lvnsgb")
- dct:language — taal
- dcat:keyword — zoekwoorden (bijv. "student", "studiefinanciering", "lening", "beurs")
- m8g:hasCompetentAuthority — koppelt aan organisatie-URI
- m8g:hasLegalResource — koppelt aan wettelijke bron URI
- m8g:sector — sector
- m8g:thematicArea — themagebied URI
- m8g:hasCost — kosten
- cpsv:produces — koppelt aan Output
- cprmv:hasDecisionModel — koppelt aan beslismodel

=== OVERIGE PROPERTIES ===
- skos:prefLabel — naam/label van organisatie of concept
- cpsv:follows — koppelt PublicService aan Rule
- cpsv:hasInput — koppelt PublicService aan Input
- eli:implements — koppelt Rule aan LegalResource

=== ORGANISATIES IN DE DATASET (skos:prefLabel waarden) ===
- Dienst Uitvoering Onderwijs — studiefinanciering
- Rijksdienst voor Ondernemend Nederland — subsidies
- Sociale Verzekeringsbank — AOW, kinderbijslag
- Uitvoeringsinstituut Werknemersverzekeringen — WW, WIA
- Directoraat-generaal Toeslagen — zorgtoeslag
- Gemeente Heusden — heusdenpas, kindpakket
- Provincie Flevoland — vergunningen
- Onderwijs, Cultuur en Wetenschap — bekostiging scholen
- Sociale Zaken en Werkgelegenheid — normenbrief

=== PUBLIEKE DIENSTEN (dct:identifier waarden) ===
- studiefinanciering (DUO)
- zorgtoeslag-lvnsgb (Toeslagen)
- ww-uitkering (UWV)
- aow-leeftijd (SVB)
- aow-leeftijd-uwv (UWV)
- isde-subsidie-dakisolatie (RVO)
- heusdenpaskindpakket (Gemeente Heusden)
- normbedragen (SZW)
- basisbekosting-vo (OCW)
- tree-felling / replacement-tree / rip-assignment / hr-onboarding (Provincie Flevoland)
"""

NL2SPARQL_SYSTEM = f"""Je bent een SPARQL-query generator voor de CODW-dataset (Nederlandse overheidsregelspecificaties).

Je taak: genereer een SPARQL SELECT query die de juiste data ophaalt voor de gebruikersvraag.

{SCHEMA_DESCRIPTION}

REGELS:
1. Genereer ALLEEN een SPARQL query, geen uitleg.
2. Wrap de query in ```sparql ... ``` codeblok.
3. Gebruik altijd de juiste prefixes.
4. Als de vraag NIET beantwoord kan worden met deze dataset, antwoord dan EXACT met: NO_DATA
5. De dataset bevat ALLEEN regelspecificaties van Nederlandse overheidsdiensten. Vragen over andere onderwerpen → NO_DATA.
6. CRUCIAAL VOOR ZOEKEN: Titels in de dataset kunnen typos bevatten! Zoek daarom ALTIJD breed:
   - Zoek op MEERDERE velden tegelijk: dct:title, dct:description, dct:identifier, EN dcat:keyword
   - Gebruik korte zoektermen (woordstammen) in FILTER, bijv. "studie" i.p.v. "studiefinanciering"
   - Combineer met OR (||) in je FILTER over meerdere velden
   - Gebruik altijd STR() rond variabelen in FILTER: CONTAINS(LCASE(STR(?var)), "zoekterm")
   - Voorbeeld pattern:
     FILTER(
       CONTAINS(LCASE(STR(?title)), "studie") ||
       CONTAINS(LCASE(STR(?desc)), "studie") ||
       CONTAINS(LCASE(STR(?id)), "studie") ||
       CONTAINS(LCASE(STR(?keyword)), "studie")
     )
7. Haal altijd relevante properties op (titel, beschrijving, organisatie, identifier, URI's).
8. Gebruik OPTIONAL voor properties die niet altijd gevuld zijn.
9. LIMIT resultaten tot 50.
"""


st.set_page_config(
    page_title="Open Regels – CODW",
    page_icon="🏛️",
    layout="wide",
)

st.markdown(f"""
<style>
    /* Hide the default Streamlit header */
    header[data-testid="stHeader"] {{
        display: none !important;
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
    auth_html = (
        f'<div class="navbar-auth">'
        f'<span class="navbar-user">{html_escape(user["name"])}</span>'
        f'</div>'
    )
elif OIDC_ENABLED:
    auth_html = ''
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

# Auth buttons (Streamlit buttons can't live inside raw HTML)
if OIDC_ENABLED:
    if authenticated:
        # Place logout button right-aligned below the navbar
        logout_col = st.columns([6, 1])
        with logout_col[1]:
            if st.button("Uitloggen", key="navbar_logout"):
                oidc_logout()
    else:
        if st.session_state.pop("oidc_error", False):
            detail = st.session_state.pop("oidc_error_detail", "")
            st.error(f"Inloggen mislukt. {detail}" if detail else "Inloggen mislukt. Probeer opnieuw.")
        login_col = st.columns([6, 1])
        with login_col[1]:
            if st.button("Inloggen", key="navbar_login"):
                oidc_login()

if not authenticated:
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
