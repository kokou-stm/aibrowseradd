from browser_use import Agent, ChatAzureOpenAI, ChatOpenAI
from browser_use.browser import ProxySettings
from browser_use import Browser, sandbox, ChatBrowserUse, ChatAzureOpenAI
from pydantic import SecretStr

from playwright_stealth import stealth_async
import os
import asyncio
from dotenv import load_dotenv
load_dotenv()
import ssl
ssl._create_default_https_context = ssl._create_unverified_context

import fitz  # pymupdf

# Sensitive data
EMAIL = "sitsopekokou@gmail.com"
PASSWORD = SecretStr("Validation1@1221")
LinkedIn_URL = "https://www.linkedin.com/in/sks-uphf/"


def load_pdf_text():
    doc = fitz.open("cv_sitsope_kokou.pdf")
    text = ""
    for page in doc:
        text += page.get_text()
    return text


#from browser_use import Browser, BrowserConfig

from browser_use import Browser

browser = Browser(
    headless=True,
    args=[
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-blink-features=AutomationControlled",
        "--disable-features=VizDisplayCompositor",
        "--ignore-certificate-errors",
        "--disable-web-security",
        "--disable-features=IsolateOrigins,site-per-process",
        "--disable-ipc-flooding-protection"
    ],
    user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    viewport={"width": 1920, "height": 1080},
    ignore_default_args=["--enable-automation"],
    disable_security=True,
    deterministic_rendering=False,  # Éviter les patterns détectables
    wait_between_actions=1.5,  # Ajouter des délais réalistes
    minimum_wait_page_load_time=2.0
)

""" browser_args=[
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-blink-features=AutomationControlled",
        "--disable-features=VizDisplayCompositor",
        "--ignore-certificate-errors",
        "--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    ]"""




async def main():
    """browser  = Browser(
        headless=True,  # Sans interface
         chromium_sandbox=False,
         cloud_proxy_country_code='us', 
         #slow_mo=100,
         user_data_dir="/tmp/browser-profile"  # Persistance pour sembler humain
    )"""

    # Initialize the model
    llm = ChatAzureOpenAI(
        model="o4-mini",
    )
    """llm = ChatOpenAI(
    model="o3",
  )"""

    "Ownaccount a694f1e4-a9aa-4fb1-a48a-e51f61b80883"
    # Create agent with the model
    agent = Agent(
        task=f"""
        Tu es un assistant virtuel qui m'aide à trouver des stages en IA.
        Suis ces étapes:
        1. Vas sur le site de https://insa-hautsdefrance.jobteaser.com/ , 
        2. connecte toi avec les informations suivantes:
        3. Mon Email: sitsopekokou@gmail.com et Mot de Passe: Validation1@1221 
        
        4. affiches moi tous les stages en IA
        5.  cliques sur le 1 er offres de stage en agents IA dans la liste
        Mes informations de CV sont dans ce document: {load_pdf_text()}

        Le lien de mon profil LinkedIn est: https://www.linkedin.com/in/sks-uphf/
        6. Postules y en utilisant mon CV et mon profil LinkedIn.
        7. Donnes moi le lien de l'offre de stage postulé et un résumé de l'offre.
        """, # Your task here
        llm=llm,
        browser=browser,
        step_timeout = 500,
    
        available_file_paths=["/Users/sekponakokou/Desktop/ownprojects/AiBrowseAgent/cv_sitsope_kokou.pdf"],
    )
    
    history = await agent.run()
    print("---- History ----")
    print(history.urls())
    print(history.action_names()  )
   
    print(history.is_done())
    print(history.total_duration_seconds())
    print(history.screenshot_paths())
    print("______Final Result______\n\n")
    print(history.final_result())
    print("---- End of History ----")


if __name__ == "__main__":
    asyncio.run(main())

"""- rajouer les infos du User actuel
- rajouer les infos du JobPreference actuel
- """