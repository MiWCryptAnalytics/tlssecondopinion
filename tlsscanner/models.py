from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class UserProfile(models.Model):
    # This line is required. Links UserProfile to a User model instance.
    user = models.OneToOneField(User)

    # The additional attributes we wish to include.
    website = models.URLField(blank=True)
    picture = models.ImageField(upload_to='profile_images', blank=True)

    # Override the __unicode__() method to return out something meaningful!
    def __unicode__(self):
        return self.user.username


## Our Model for Session Certificate and Report

def session_default():
    return ""

def pubkey_default():
    return ""

def certificate_default():
    return ""

def serverdetails_default():
    return ""

class PublicKey(models.Model):
    pubkey_type = models.TextField()
    pubkey_size = models.PositiveSmallIntegerField()
    pubkey_data = models.TextField()
    pubkey_data_name = models.TextField()

class Certificate(models.Model):
    pem = models.TextField()
    version = models.PositiveSmallIntegerField()
    serial = models.TextField()
    sigAlgo = models.TextField()
    issuer = models.TextField()
    notBefore =  models.DateTimeField()
    notAfter =  models.DateTimeField()
    life_at_report = models.TextField()
    subject = models.TextField()
    ext_bc = models.TextField()
    ext_ku = models.TextField()
    ext_eku = models.TextField()
    ext_aia = models.TextField()
    ext_crl = models.TextField()
    ext_cp = models.TextField()
    ext_san = models.TextField()
    ext_aki = models.TextField()
    pubkey = models.OneToOneField(PublicKey, default=pubkey_default)

class ServerDetails(models.Model):
    server_geo  = models.TextField()
    server_whois = models.TextField()

class Session(models.Model):
    date = models.DateTimeField()
    hostname = models.TextField()
    server_details = models.OneToOneField(ServerDetails, default=serverdetails_default)
    server_ip = models.GenericIPAddressField()
    server_port = models.IntegerField()
    server_random = models.TextField()
    server_random_date = models.DateField()
    client_random = models.TextField()
    client_random_date = models.DateField()
    master_key = models.TextField()
    session_id = models.TextField()
    session_ticket = models.TextField()
    session_ticket_lifetime = models.TextField()
    server_cipher = models.TextField()
    tls_version = models.TextField()
    tls_kx = models.TextField()
    tls_auth = models.TextField()
    tls_enc = models.TextField()
    tls_cmode = models.TextField()
    tls_mac = models.TextField()
    certificate = models.OneToOneField(Certificate, default=certificate_default)
    server_http_response = models.TextField()
    
class ScanResult(models.Model):
    openssl_ciphers = models.TextField()
    openssl_version = models.TextField()
    session = models.OneToOneField(Session, default=session_default)
    date = models.DateTimeField()
    requestor_ip = models.GenericIPAddressField()



