from django.db import models
 

 
from django.contrib.auth.models import User  # ou ton propre modèle utilisateur

class GmailToken(models.Model):
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        # si l'utilisateur est supprimé → token supprimé
        related_name='gmail_token'
    )
    token = models.TextField()                  # access_token actuel
    refresh_token = models.TextField()          # très important, permet de rafraîchir indéfiniment
    token_uri = models.TextField(default='https://oauth2.googleapis.com/token')
    client_id = models.TextField()
    client_secret = models.TextField()
    scopes = models.JSONField(default=list)     # ex: ["https://www.googleapis.com/auth/gmail.readonly"]
    created_at = models.DateTimeField(auto_now_add=True)
    
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Token Gmail de {self.user.email}"
 
class JobPreference(models.Model):
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='job_preferences',
     
    )
    cv = models.FileField(upload_to='cv/')

    contrat = models.JSONField(default=list, blank=True)
    location = models.JSONField(default=list, blank=True)
    pays = models.JSONField(default=list, blank=True)

    duree = models.PositiveIntegerField(null=True, blank=True)

    langue = models.JSONField(default=list, blank=True)
    domaine = models.JSONField(default=list, blank=True)

    anotherinfo = models.TextField(blank=True, null=True)

    date_created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Preferences #{self.id}"


    def __str__(self):
        return f"{self.job_title} chez {self.company_name} postulé par {self.user.email}"
# Create your models here.
