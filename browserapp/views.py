# views.py

import os
from pydantic import SecretStr
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # toujours en devimport os
os.environ["ANONYMIZED_TELEMETRY"] = "false"

# Sensitive data
EMAIL = "sitsopekokou@gmail.com"
PASSWORD = SecretStr("Validation1@1221")
LinkedIn_URL = "https://www.linkedin.com/in/sks-uphf/"

from browser_use import Browser

import re
import html
from bs4 import BeautifulSoup
import base64
import json
from browser_use import Tools, ActionResult

from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse

from django.contrib.auth import login
from django.contrib.auth.models import User
from django.conf import settings
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from django.shortcuts import get_object_or_404

from base64 import urlsafe_b64decode
from browser_use import Agent, ChatAzureOpenAI, ChatOpenAI
from browser_use.browser import ProxySettings
from browser_use import Browser, sandbox, ChatBrowserUse, ChatAzureOpenAI


from playwright_stealth import stealth_async
import os
import base64
import asyncio
from dotenv import load_dotenv
load_dotenv()
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
from bs4 import BeautifulSoup
import html
import re

import fitz  # pymupdf
from .models import * 
tools = Tools()

 
 


SCOPES = ['https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/userinfo.email',   # ← ajoute cette ligne
           'openid']
CREDENTIALS_PATH = os.path.join(settings.BASE_DIR, 'config', 'credentials.json')


def send_job_infos(request):
    if request.method == "POST":
        contrat = request.POST.getlist('contrat[]')
        location = request.POST.getlist('location[]')
        pays = request.POST.getlist('pays[]')
        langue = request.POST.getlist('langue[]')
        domaine = request.POST.getlist('domaine[]')
        print("Received job infos:", contrat, location, pays, langue, domaine)
        #Create Json with this information
        job_infos = {
            "contrat": contrat,
            "location": location,
            "pays": pays,
            "langue": langue,
            "domaine": domaine
        }
        if request.user.is_authenticated:
            infos, created = JobPreference.objects.get_or_create(user=request.user)
            if created:
                print("Created new JobPreferences for user:", request.user.email)
            infos.cv = request.FILES.get('cv')
            infos.contrat = contrat
            infos.location = location
            infos.pays = pays
            infos.langue = langue
            infos.domaine = domaine
            infos.save()
            print("Saved job infos for user:", request.user.email)
        return JsonResponse({"status": "success"})
    return JsonResponse({"status": "error", "message": "Invalid request."}, status=400)



def get_flow():
    """Fonction utilitaire pour éviter de répéter le code"""
    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_PATH, SCOPES)
    flow.redirect_uri = 'http://127.0.0.1:8000/oauth2callback'
    return flow


def google_login(request):
    flow = get_flow()
    auth_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    request.session['state'] = state
    return redirect(auth_url)


def oauth2callback(request):
    flow = get_flow()
    flow.fetch_token(authorization_response=request.build_absolute_uri())
    credentials = flow.credentials

    # Récupérer l'email de l'utilisateur via Google
    service = build('oauth2', 'v2', credentials=credentials)
    user_info = service.userinfo().get().execute()
    email = user_info['email']

    # Créer ou récupérer l'utilisateur Django
    user, created = User.objects.get_or_create(
        username=email,
        defaults={'email': email}
    )
    if created:
        user.set_unusable_password()
        user.save()

    # Sauvegarder ou mettre à jour le token dans la BDD
    GmailToken.objects.update_or_create(
        user=user,
        defaults={
            'token': credentials.token,
            'refresh_token': credentials.refresh_token or '',  # parfois None la 1ère fois
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
        }
    )

    # Connecter l'utilisateur (facultatif si tu veux une session Django)
    login(request, user)

    return redirect('gmail_success')


def get_gmail_service(user_id):
    """Retourne un service Gmail fonctionnel à partir du token stocké"""
    try:
        user = User.objects.get(id=user_id)
        token_obj = GmailToken.objects.get(user=user)
    except (User.DoesNotExist, GmailToken.DoesNotExist):
        return None

    creds = Credentials(
        token=token_obj.token,
        refresh_token=token_obj.refresh_token,
        token_uri=token_obj.token_uri,
        client_id=token_obj.client_id,
        client_secret=token_obj.client_secret,
        scopes=token_obj.scopes
    )

    # Rafraîchir si besoin
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        # Sauvegarder le nouveau token
        token_obj.token = creds.token
        token_obj.save()

    return build('gmail', 'v1', credentials=creds)



def get_gmail(request):
    if not request.user.is_authenticated:
        return JsonResponse({'error': 'Non authentifié'}, status=401)

    service = get_gmail_service(request.user.id)
    if not service:
        return JsonResponse({'error': 'Accès Gmail non trouvé'}, status=401)

    # Récupère les 10 emails de l'onglet Principal
    
    results = service.users().messages().list(
        userId='me',
        maxResults=3,
        q='category:primary'
    ).execute()

    messages = results.get('messages', [])
    emails = []

    def decode(email_body):
        """Décode le body base64url"""
        return base64.urlsafe_b64decode(email_body.encode('UTF-8')).decode('UTF-8', errors='ignore')

    for msg in messages:
        msg_data = service.users().messages().get(
            userId='me',
            id=msg['id'],
            format='full'
        ).execute()

        headers = msg_data['payload'].get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(sans sujet)')
        from_header = next((h['value'] for h in headers if h['name'] == 'From'), 'Inconnu')
        date = next((h['value'] for h in headers if h['name'] == 'Date'), '')

        # Extraction du contenu
        text_content = ""
        html_content = ""

        payload = msg_data.get("payload", {})

      
        # Mail simple (non multipart)
        if "body" in payload and payload["body"].get("data"):
            text_content = decode(payload["body"]["data"])

        # Mail multipart
        if "parts" in payload:
            for part in payload["parts"]:
                mime = part.get("mimeType")
                body = part.get("body", {})

                if body.get("data"):
                    decoded = decode(body["data"])

                    if mime == "text/plain":
                        text_content += decoded
                    elif mime == "text/html":
                        html_content += decoded
        

        emails.append({
            'from': from_header,
            'subject': subject,
            'date': date,
            'text': clean_text_for_llm(text_content),
            #'html': html_content.strip(),
            'internalDate': int(msg_data['internalDate'])
        })

    # Tri comme Gmail (récent → ancien)
    emails.sort(key=lambda x: x['internalDate'], reverse=True)
    print("Fetched emails:", emails)
    return JsonResponse({
        'emails': emails,
        'user_email': request.user.email,
        'count': len(emails),
        'source': 'Primary tab only (category:primary)',
    })


def gmail_success(request):
    if not request.user.is_authenticated:
        return redirect('home')

    service = get_gmail_service(request.user.id)
    if not service:
        return render(request, 'error.html', {'error': 'Aucun accès Gmail trouvé'})

    results = service.users().messages().list(userId='me', maxResults=15).execute()
    messages = results.get('messages', [])

    emails = []
    for msg in messages:
        msg_data = service.users().messages().get(
            userId='me', id=msg['id'], format='metadata',
            metadataHeaders=['From', 'Subject', 'Date']
        ).execute()
        headers = msg_data['payload']['headers']
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(sans sujet)')
        from_ = next((h['value'] for h in headers if h['name'] == 'From'), 'Inconnu')
        emails.append({'from': from_, 'subject': subject})

    return render(request, 'success.html', {
        'emails': emails,
        'user_email': request.user.email
    })


def gmail_logout(request):
    if request.user.is_authenticated:
        GmailToken.objects.filter(user=request.user).delete()
    return redirect('home')


def home(request):
    context = {}
    if request.user.is_authenticated:
        #get or 404
        infos = JobPreference.objects.filter(user=request.user).first()
        if not infos:
            return render(request, 'index.html')
        data = {
            "user_id": infos.user.id,
            "cv_url": infos.cv.url if infos.cv else None,
            "contrat": infos.contrat,
            "location": infos.location,
            "pays": infos.pays,
            "duree": infos.duree,
            "langue": infos.langue,
            "domaine": infos.domaine,
            "anotherinfo": infos.anotherinfo,
            "date_created": infos.date_created.isoformat(),
        }
        context['job_infos'] = data
    return render(request, 'index.html', context)

def gmail_auth(request):
  creds = None
  credentials_path = os.path.join(settings.BASE_DIR, 'config', 'credentials.json')
  token_path = os.path.join(settings.BASE_DIR, 'config', 'token.json')
  # The file token.json stores the user's access and refresh tokens, and is
  # created automatically when the authorization flow completes for the first
  # time.
  if os.path.exists(token_path):
    creds = Credentials.from_authorized_user_file(token_path, SCOPES)
  flow.redirect_uri = 'http://127.0.0.1:8000/oauth2callback'
  # If there are no (valid) credentials available, let the user log in.
  if not creds or not creds.valid:
    if creds and creds.expired and creds.refresh_token:
      creds.refresh(Request())
    else:
      flow = InstalledAppFlow.from_client_secrets_file(
          credentials_path, SCOPES
      )
      creds = flow.run_local_server(port=0)
    # Save the credentials for the next run
    with open(token_path, "w") as token:
      token.write(creds.to_json())

  try:
    # Call the Gmail API
    service = build("gmail", "v1", credentials=creds)
    results = service.users().labels().list(userId="me").execute()
    labels = results.get("labels", [])

    if not labels:
      print("No labels found.")
      return
    print("Labels:")
    for label in labels:
      print(label["name"])

  except Exception as error:
    # TODO(developer) - Handle errors from gmail API.
    print(f"An error occurred: {error}")

  return render(request, 'success.html')




def load_pdf_text():
    doc = fitz.open("cv_sitsope_kokou.pdf")
    text = ""
    for page in doc:
        text += page.get_text()
    return text






def clean_text_for_llm(raw_email_body: str) -> str:
    """
    Transforme n'importe quel corps d'email (HTML, CSS, multipart)
    en texte humain ultra-propre avec les liens intacts dans le texte.
    """
    if not raw_email_body:
        return ""

    # 1. Décode les &nbsp;, &amp;, etc.
    text = html.unescape(raw_email_body)

    # 2. BeautifulSoup parse tout
    soup = BeautifulSoup(text, "lxml")

    # 3. Supprime le bruit (scripts, styles, etc.)
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()

    # 4. Remplace chaque <a href="..."> par : texte (lien)
    # → devient super lisible : "Cliquez ici[](https://...)"
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith(('http://', 'https://')):
            link_text = a.get_text(strip=True)
            if link_text.lower() in ['cliquez ici', 'ici', 'confirmer', 'activer', 'verify']:
                a.replace_with(f"{link_text} {href}")
            else:
                a.replace_with(f"{link_text} ({href})")

    # 5. Extrait le texte pur
    clean = soup.get_text(separator="\n")

    # 6. Nettoie les sauts de ligne et espaces multiples
    clean = re.sub(r'\n\s*\n', '\n\n', clean)   # max 2 sauts
    clean = re.sub(r'[ \t]+', ' ', clean)       # espaces multiples → 1
    clean = re.sub(r'\n[ \t]+', '\n', clean)    # indentation
    clean = clean.strip()

    return clean

from browser_use import Tools, ActionResult
import json
import base64



# Votre clean_text_for_llm reste le même
def clean_text_for_llm(raw_email_body: str) -> str:
    """
    Transforme n'importe quel corps d'email (HTML, CSS, multipart)
    en texte humain ultra-propre avec les liens intacts dans le texte.
    """
    if not raw_email_body:
        return ""
    # 1. Décode les &nbsp;, &amp;, etc.
    text = html.unescape(raw_email_body)
    # 2. BeautifulSoup parse tout
    soup = BeautifulSoup(text, "lxml")
    # 3. Supprime le bruit (scripts, styles, etc.)
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    # 4. Remplace chaque <a href="..."> par : texte (lien)
    # → devient super lisible : "Cliquez ici[](https://...)"
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith(('http://', 'https://')):
            link_text = a.get_text(strip=True)
            if link_text.lower() in ['cliquez ici', 'ici', 'confirmer', 'activer', 'verify']:
                a.replace_with(f"{link_text} {href}")
            else:
                a.replace_with(f"{link_text} ({href})")
    # 5. Extrait le texte pur
    clean = soup.get_text(separator="\n")
    # 6. Nettoie les sauts de ligne et espaces multiples
    clean = re.sub(r'\n\s*\n', '\n\n', clean) # max 2 sauts
    clean = re.sub(r'[ \t]+', ' ', clean) # espaces multiples → 1
    clean = re.sub(r'\n[ \t]+', '\n', clean) # indentation
    clean = clean.strip()
    return 

from datetime import datetime, timedelta
import email.utils

tools = Tools()

@tools.action("Récupérer les 10 derniers emails de l'onglet Principal Gmail")
def list_email(email: str) -> ActionResult:
    """
    Récupère les 10 derniers emails de l'onglet Principal (Primary) de Gmail.
    Args:
        email: l'adresse email Gmail
    """
    user = User.objects.filter(email=email).first()
    if not user:
        return ActionResult(
            extracted_content=None,
            error="Utilisateur non trouvé",
            success=False,
            is_done=True
        )
  
    service = get_gmail_service(user.id)
    if not service:
        return ActionResult(
            extracted_content=None,
            error="Accès Gmail non autorisé ou token expiré",
            success=False,
            is_done=True
        )
    try:
        results = service.users().messages().list(
            userId='me',
            maxResults=5, # Augmenté à 10 pour plus de résultats
            q='category:primary (from:jobteaser OR from:no-reply@jobteaser.com OR from:@jobteaser.com OR from:notifications@jobteaser.com OR from:noreply@notifications.jobteaser.com)' # Élargi les expéditeurs, supprimé newer_than pour capturer plus
        ).execute()
        messages = results.get('messages', [])
        if not messages:
            return ActionResult(
                extracted_content=json.dumps({
                    'emails': [],
                    'user_email': email,
                    'count': 0,
                    'source': 'Primary tab (no emails found)'
                }, ensure_ascii=False, indent=2),
                success=True,
                is_done=True
            )
        emails = []
        def decode_body(data):
            if not data:
                return ""
            return base64.urlsafe_b64decode(data + '===').decode('utf-8', errors='ignore')
        for msg in messages:
            msg_data = service.users().messages().get(
                userId='me',
                id=msg['id'],
                format='full'
            ).execute()
            headers = {h['name']: h['value'] for h in msg_data['payload'].get('headers', [])}
          
            subject = headers.get('Subject', '(sans sujet)')
            from_header = headers.get('From', 'Inconnu')
            date = headers.get('Date', '')
            internal_date = int(msg_data.get('internalDate', 0)) # Pour tri précis
            # Extraction du corps
            text_content = ""
            html_content = ""
            def extract_part(part):
                if 'data' in part.get('body', {}):
                    data = part['body']['data']
                    decoded = decode_body(data)
                    if part['mimeType'] == 'text/plain':
                        return decoded, ""
                    elif part['mimeType'] == 'text/html':
                        return "", decoded
                return "", ""
            payload = msg_data['payload']
            if payload.get('mimeType') == 'multipart/alternative' or payload.get('mimeType') == 'multipart/mixed':
                for part in payload.get('parts', []):
                    t, h = extract_part(part)
                    text_content += t
                    html_content += h
            else:
                text_content, html_content = extract_part(payload)
           
            # Si text_content vide, utiliser html_content
            body = text_content if text_content.strip() else html_content
            cleaned_body = clean_text_for_llm(body)
           
            emails.append({
                'from': from_header,
                'subject': subject,
                'date': date,
                'text': cleaned_body,
                'body': html_content.strip() if html_content else None, # Commenté comme avant
                'id': msg['id'],
                'internal_date': internal_date # Pour tri
            })
        # Tri par date (le plus récent en haut)
        emails.sort(key=lambda x: x['internal_date'], reverse=True)
        
        # Filtre pour les emails dans ±10 minutes de now
        import time
        now_ms = int(time.time() * 1000)
        ten_min_ms = 10 * 60 * 1000
        filtered_emails = [email for email in emails if abs(email['internal_date'] - now_ms) <= ten_min_ms]
        
        # Renvoie le JSON complet pour que l'agent parse lui-même
        result_json = json.dumps({
            "user_email": email,
            "count": len(filtered_emails),
            "source": "Gmail Primary tab (category:primary)",
            "emails": filtered_emails
        }, ensure_ascii=False, indent=2)
       
        print("Gmail fetch result:", result_json) # Pour debug
       
        return ActionResult(
            extracted_content=result_json,
            
        )
     
    except Exception as e:
        return ActionResult(
            extracted_content=None,
            error=f"Erreur lors de la lecture Gmail : {str(e)}",
            
        )

from datetime import datetime
from asgiref.sync import sync_to_async
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import threading
from datetime import datetime


# views.py
import threading
import asyncio
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from browser_use import Browser, Agent, ChatAzureOpenAI
 

 
import fitz

import os
from openai import AzureOpenAI

endpoint = "https://realtimekokou.openai.azure.com/"
model_name = "o4-mini"
deployment = "o4-mini"
def chat_with_azure_openai(email_list: str) :
    subscription_key = os.getenv("AZURE_OPENAI_API_KEY")
    api_version = "2024-12-01-preview"

    client = AzureOpenAI(
        api_version=api_version,
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
        api_key=subscription_key,
    )

    response = client.chat.completions.create(
        messages=[
            {
                "role": "system",
                "content": "You are a helpful assistant.",
            },
            {
                "role": "user",
                "content": f"Extract for this list of email , the most recent password reset link, and return it in the format: 'Password Reset Link: <link>': {email_list} ",
            }
        ],
        #max_tokens=4096,
        temperature=1.0,
        top_p=1.0,
        model=deployment
    )

    return response.choices[0].message.content

#print("Email extract" ,"=="*4, chat_with_azure_openai({'user_email': 'ablamawunyosekpona@gmail.com', 'count': 3, 'source': 'Gmail Primary tab (category:primary)', 'emails': [{'from': 'JobTeaser Connect <noreply@notifications.jobteaser.com>', 'subject': 'Reset your password', 'date': 'Mon, 01 Dec 2025 00:20:28 +0000 (UTC)', 'text': 'Click on the link to reset your password: https://connect.jobteaser.com/reset_password/edit?reset_token=OWYxZjlhODAtMGIxMS00MWY1LTg4MDAtNzgxYzQyZTkzMTlj.117705fa572161d516bc4d8780cbeb4eaea698dc7f2c614a81f20e7d3a9d6017', 'id': '19ad748456814121'}, {'from': '"Espace Carrières INSA Lyon" <notification@jobteaser.com>', 'subject': 'INSA Lyon: upcoming events 🎉', 'date': 'Mon, 24 Nov 2025 01:35:50 +0000 (UTC)', 'text': '', 'id': '19ab380c27c55d5c'}, {'from': 'JobTeaser <notification@jobteaser.com>', 'subject': 'Welcome to JobTeaser, Kokou!', 'date': 'Fri, 21 Nov 2025 08:04:31 +0000 (UTC)', 'text': '', 'id': '19aa5718630389f3'}]}))

def _run_jobteaser_agent(email: str):
    async def _inner():
        print(f"Lancement agent JobTeaser pour {email} à {asyncio.get_event_loop()}")

        # Nouveau browser à chaque fois → obligatoire dans un thread
        browser = Browser(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--ignore-certificate-errors",
            ],
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            viewport={"width": 1920, "height": 1080},
        )

        llm = ChatAzureOpenAI(model="o4-mini")

        def load_cv():
            doc = fitz.open("/Users/sekponakokou/Desktop/ownprojects/AiBrowseAgent/cv_sitsope_kokou.pdf")
            return "".join(page.get_text() for page in doc)

        agent = Agent(
            # task in english
            task=f"""
            You are my assistant for applying to job offers. Your complete mission:

            1. Go to https://insa-hautsdefrance.jobteaser.com/
            2. Create an account with the email: {email}
             - Password: create a secure password (e.g., JobTeaser2025!Kokou)
            - Fill in all personal information from the CV below:
            {load_cv()}

            - if the terms of service or privacy policy pop-up appears, accept them to proceed, if its pdf, dont open it, just accept.
            
            3. If the account is already existing, proceed to login instead. If the password is incorrect, use the "Forgot Password" feature to reset it
            and get the activation link sent to the email with the steps below:
             - If the account exists, click on "Forgot Password"
             - get the email list with the tool **list_email** withe the email="{email}"
             - Search through all and get the resent password reset email
             -  Click on the link to reset your password and set a new password
             -login with the new password
            
            4. Verify and activate the account by checking Gmail:
            
            ACTIVATION LOOP - Repeat until you find the activation link:

            a) Call list_email with email="{email}"
            b) Parse the returned JSON 'emails' array. For each email, check:
            - Subject contains: "JobTeaser", "activate", "confirm", "verify", "account", "welcome"
            - Body ('text') contains a link with "jobteaser" and ("activate" OR "confirm" OR "verify")
            c) If activation link found:
            - Extract the complete URL
            - Click on it in the browser
            - ...
            d) If NO activation link found:
            - Wait 60 seconds (1 minute)
            - Repeat from step a)
            Repeat this loop until the account is activated.

            Expected final result:
            JobTeaser account created and ACTIVATED for {email}
            Return the final password used and the email used.
             
            Screenshot showing activation success page
            """,
            llm=llm,
            browser=browser,
            step_timeout=600,
            available_file_paths=["/Users/sekponakokou/Desktop/ownprojects/AiBrowseAgent/cv_sitsope_kokou.pdf"],
            tools=tools,  # tes tools Gmail
        )
        events = []
         
        events = []

        async def on_step_start(agent):
            step_number = agent.history.number_of_steps()
            events.append({'type': 'step_start', 'step': step_number})

        async def on_step_end(agent):
            events.append({
                'type': 'step_end', 
                'actions': agent.history.action_names(),
                'urls': agent.history.urls()
            })

 

        history = await  agent.run(on_step_start=on_step_start, on_step_end=on_step_end)
        print("AGENT TERMINÉ →", history.final_result())
        with open(f"jobteaser_agent_history_{email.replace('@', '_at_')}.txt", "w") as f:
            f.write(str(history))
        # Get the final extracted content (last step)
        
        """print("---- Agent Events ----" )
        for event in events:
            print(event)"""
        # Check if agent completed successfully
        is_done = history.is_done()
        print(f"Agent done status: {is_done}")
        is_successful = history.is_successful()
        print(f"Agent success status: {is_successful}")

    # Créer un nouveau loop + exécuter
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_inner())
    finally:
        loop.close()

 
 
@csrf_exempt
def run_main(request):
     
    email = request.user.email

    thread = threading.Thread(target=_run_jobteaser_agent, args=(email,), daemon=True)
    thread.start()

    return render(request, 'index.html')



def _run_job_apply(email: str):
    async def _inner():
        print(f"Lancement job apply pour {email} à {asyncio.get_event_loop()}")

        # Nouveau browser à chaque fois → obligatoire dans un thread
        browser = Browser(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--ignore-certificate-errors",
            ],
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            viewport={"width": 1920, "height": 1080},
        )

        llm = ChatAzureOpenAI(model="o4-mini")

        agent = Agent(
        task=f"""
        Tu es un assistant virtuel qui m'aide à trouver des stages en IA.
        Suis ces étapes:
        1. Vas sur le site de https://insa-hautsdefrance.jobteaser.com/ , 
        2. connecte toi avec les informations suivantes:
        3. Mon Email: sitsopekokou@gmail.com et Mot de Passe: Validation1@1221 

        Mes informations de recherche sont : 
        
        4. affiches moi tous les stages en IA
        5.  cliques sur les 2 premiers  offres de stage en agents IA dans la liste
        Mes informations de CV sont dans ce document: {load_pdf_text()}

        Le lien de mon profil LinkedIn est: https://www.linkedin.com/in/sks-uphf/
        6. Postules y en utilisant mon CV et mon profil LinkedIn.
        7. Donnes moi le lien de l'offre de stage postulé et un résumé de l'offre.
        """,
            llm=llm,
            browser=browser,
            step_timeout=600,
            tools=tools,  # tes tools Gmail
        )
        history = await agent.run()
        print("JOB APPLY AGENT TERMINÉ →", history.final_result())

    # Créer un nouveau loop + exécuter
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_inner())
    finally:
        loop.close()

@csrf_exempt
def apply_job(request):
    email = request.user.email

    thread = threading.Thread(target=_run_job_apply, args=(email,), daemon=True)
    thread.start()

    return render(request, 'index.html')


def create_upload_dir():
    upload_dir = os.path.join(settings.BASE_DIR, 'uploads')
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
    return upload_dir

def handle_uplaod_file(f):
    upload_dir = create_upload_dir()
    file_path = os.path.join(upload_dir, f.name)
    with open(file_path, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    return file_path


@csrf_exempt
def upload_cv(request):
    if request.method == 'POST' and request.FILES.get('cv'):
        cv_file = request.FILES['cv']
        file_path = handle_uplaod_file(cv_file)
        return JsonResponse({'status': 'success', 'file_path': file_path})
    return JsonResponse({'status': 'error', 'message': 'Invalid request.'}, status=400)

@csrf_exempt
def upload_another_file(request):
    if request.method == 'POST' and request.FILES.get('anotherfile'):
        another_file = request.FILES['anotherfile']
        file_path = handle_uplaod_file(another_file)
        return JsonResponse({'status': 'success', 'file_path': file_path})
    return JsonResponse({'status': 'error', 'message': 'Invalid request.'}, status=400)

@csrf_exempt
def upload_cover_letter(request):
    if request.method == 'POST' and request.FILES.get('coverletter'):
        cover_letter_file = request.FILES['coverletter']
        file_path = handle_uplaod_file(cover_letter_file)
        return JsonResponse({'status': 'success', 'file_path': file_path})
    return JsonResponse({'status': 'error', 'message': 'Invalid request.'}, status=400)

@csrf_exempt
def upload_portfolio(request):
    if request.method == 'POST' and request.FILES.get('portfolio'):
        portfolio_file = request.FILES['portfolio']
        file_path = handle_uplaod_file(portfolio_file)
        return JsonResponse({'status': 'success', 'file_path': file_path})
    return JsonResponse({'status': 'error', 'message': 'Invalid request.'}, status=400)

def upload_certificates(request):
    if request.method == 'POST' and request.FILES.get('certificates'):
        certificates_file = request.FILES['certificates']
        file_path = handle_uplaod_file(certificates_file)
        return JsonResponse({'status': 'success', 'file_path': file_path})
    return JsonResponse({'status': 'error', 'message': 'Invalid request.'}, status=400)

os.environ['BROWSERAPP_ENV'] = 'development'  # or 'production'
os.environ["PLAYWRIGHT_DISABLE_CSP"] = "true"
os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "0"  # Téléchargement des navigateurs dans le dossier du projet
os.environ["PWDEBUG"] = "1"  # Active le mode debug de Playwright
os.environ["PLAYWRIGHT_HEADLESS"] = "1"  # Exécution en mode headless
os.environ["OPENAI_API_TYPE"] = "azure"
os.environ["OPENAI_API_VERSION"] = "2024-12-01-preview"
os.environ["OPENAI_API_BASE"] = endpoint
os.environ["OPENAI_API_KEY"] = os.getenv("AZURE_OPENAI_API_KEY")
os.environ["AZURE_OPENAI_API_KEY"] = os.getenv("AZURE_OPENAI_API_KEY")
os.environ["AZURE_OPENAI_ENDPOINT"] = os.getenv("AZURE_OPENAI_ENDPOINT")        
    

def test_view(request):
    return JsonResponse({"status": "ok"})

@csrf_exempt
def run_test_agent(request):
    email = request.user.email

    thread = threading.Thread(target=_run_jobteaser_agent, args=(email,), daemon=True)
    thread.start()

    return JsonResponse({"status": "agent started"})

@csrf_exempt
def run_test_apply(request):
    email = request.user.email

    thread = threading.Thread(target=_run_job_apply, args=(email,), daemon=True)
    thread.start()

    return JsonResponse({"status": "job apply agent started"})

@csrf_exempt
def run_test_azure_chat(request):
    email_list = request.POST.get('email_list', '')
    response = chat_with_azure_openai(email_list)
    return JsonResponse({"response": response})

@csrf_exempt
def run_test_email_extraction(request):
    email = request.user.email
    action_result = list_email(email)
    if action_result.success:
        return JsonResponse({"extracted_content": action_result.extracted_content})
    else:
        return JsonResponse({"error": action_result.error}, status=500)
    

@csrf_exempt
def save_job_infos(request):
    if request.method == 'POST':
        contrat = request.POST.getlist('contrat[]')
        location = request.POST.getlist('location[]')
        pays = request.POST.getlist('pays[]')
        langue = request.POST.getlist('langue[]')
        domaine = request.POST.getlist('')
        return copyright
    
def create_chat_folder(request):
    return render(request, {})
