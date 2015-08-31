## Views.py for tlsscanner for TLS Second Opinion
## by MiWCryptAnalytics 2015
from django.views.generic import View
from django.shortcuts import render, render_to_response
from django.utils import html

from tlsscanner.forms import UserForm, UserProfileForm

from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseRedirect, HttpResponse
from django.template import RequestContext
from django.conf import settings

## validity periods
from datetime import datetime

## grep'n
import re
## hex'n
import binascii
## debug'n
import pprint

## maps for report
from geoip import geolite2
from collections import OrderedDict
from django.core import serializers

## For HTTP
import requests

## Local Modules
from . import scanner
from . import opinions
from . import comments
from . import models

## Get data from Apnic (thanks APNIC!)
rdap_url = "https://rdap.apnic.net/ip/%s"

def format_certificate(certificate):
    certificate.replace("\n", "<br>")
    return

def dictToText(dictobj):
    returnstring = ""
    for k in dictobj.keys():
        returnstring+="%s " % (dictobj.get(k))
    return returnstring

def parseJCard(jcard):
    returnjcard = {}
    if (jcard[0] != "vcard"):
        return "Bad JCard"
    for prop in jcard[1]:
        if (prop[0]=="adr"):
                  returnjcard[str(prop[0])] = prop[1]['label']
        else:
            returnjcard[str(prop[0])] = prop[3]
    return dictToText(returnjcard)
        

## from https://stackoverflow.com/questions/4581789/how-do-i-get-user-ip-address-in-django
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def index(request):
    return render(request, 'index.html')

def do(request, targethost, targetport):
    returned = scanner.vanillaConnect(targethost, int(targetport))
    
    if type(returned) == str:
        
        error_message = """Sorry, we could not connect to host %s on tcp port %s.\n
                This domain might be unregistered, resolve to a private IP, or might not be listening with TLS on port %s.\n
                \n
                Please try again later\n Error: %s\n
                \n
                Report was run at %s""" % (targethost, targetport, targetport, returned, datetime.now())
        context_dict = {'error': html.linebreaks(error_message, autoescape=False)}
        return render(request, 'error.html', context_dict)
    
    else:
        scan_date = returned[0][0]
        openssl_ciphers = returned[0][1]
        server_certificate = returned[1]
        connection_params = returned[2]
        server_ip = returned[3][0]
        server_port = returned[3][1]
        openssl_version = returned[4]
        server_geo = returned[5]
        server_whois = OrderedDict()
        server_http_response = returned[6]

        ## whois stuff
        whois_lookup = requests.get(rdap_url % server_ip, verify=True)
        if (whois_lookup.status_code==200):
            whois_json=whois_lookup.json()
            server_whois['name'] = whois_json.get('name')
            server_whois['handle'] = whois_json.get('handle')
            ## construct link details
            whois_links = whois_json.get('links')
            return_whois_links = []
            if (whois_links):
                for links in whois_links:
                    linkstring = '%s<a href=\"%s\"> %s</a> (Type: %s)' % (links.get('rel'), links.get('href'), links.get('value'), links.get('type'))
                    return_whois_links.append(linkstring)
                server_whois['links'] = return_whois_links

            ## construct entity details (deals with embeded entities within entities)
            whois_entities = whois_json.get('entities')
            new_whois_entities = []
            return_whois_entities = []
            # flatten entities in 1 level in tree (ARIN db)
            for entity in whois_entities:
                new_whois_entities.append(entity)
                if ( entity.get('entities') ):
                    for subentity in entity['entities']:
                        new_whois_entities.append(subentity)
                        
            for entity in new_whois_entities:
                handlestring = ""
                jcardstring = ""
                rolestrings = ""
                if (entity.get('links')):
                    handlestring ='<a href=\"%s\"><b>Handle:</b> %s</a> ' % (entity.get('handle'), entity.get('links')[0]['href'])
                else:
                    handlestring = '<b>Handle:</b> %s' % (entity.get('handle'))
                if (entity.get('roles')): 
                    rolesstring = 'Roles: %s ' % entity.get('roles')
                if (entity.get('vcardArray')):
                    jcard = '<b>jcard</b>: %s ' % parseJCard(entity['vcardArray'])
                entitystring = handlestring + rolesstring + jcard
                return_whois_entities.append(entitystring)
            server_whois['entities'] = return_whois_entities
        else:
            server_whois = {'name' : 'Unknown', 'handle' : 'Unknown'}
##        server_whois['entities'] = pprint.pformat(whois_json['entities'])
##        server_whois['name'] = whois_lookup['nets'][0]['name']
##        server_whois['description'] = whois_lookup['nets'][0]['description']
##        server_whois['address'] = whois_lookup['nets'][0]['address']
##        server_whois['city'] = whois_lookup['nets'][0]['city']
##        server_whois['state'] = whois_lookup['nets'][0]['state']
##        server_whois['country'] = whois_lookup['nets'][0]['country']
##        server_whois['asn'] = whois_lookup['asn']
##        server_whois['asn_cidr'] = whois_lookup['asn_cidr']
##        server_whois['handle'] = whois_lookup['nets'][0]['handle']
##        server_whois['asn_date'] = whois_lookup['asn_date']
                
        
        
        ## Negotiated CipherSuite Details
        
        ciphersuite = connection_params['cipher']
        tls_version = connection_params['tls_version']
        
        pattern = r"([\d|\w-]+)\s+([\w\d\.]+)\s+Kx=(\w+)\s+Au=(\w+)\s+Enc=([\d|\w()]+)\s+Mac=([\w\d]+)"
        prog = re.compile(pattern)
        result = prog.match(connection_params['cipher_description'])
        
        tls_kx = result.group(3)
        tls_auth = result.group(4)
        tls_mac = result.group(6)
        tls_enc = result.group(5)

        

        ## ECDH and DH kx from cipher description Missing e from regex so we grab from ciphersuite
        if 'ECDHE' in ciphersuite:
            tls_kx = "ECDHE"
        elif 'ECDH' in ciphersuite:
            tls_kx = "ECDH"
        elif 'DHE' in ciphersuite:
            tls_kx = "DHE"
        elif 'DH' in ciphersuite:
            tls_kx = "DH"

        ## set auth type from ciphersuite
        if 'ECDSA' in ciphersuite:
            tls_auth = "ECDSA"

        ## handle both GCM and CBC cipher desc as standard name
        if 'AES' in tls_enc:
            if '256' in tls_enc:
                tls_enc = "AES-256"
            elif '128' in tls_enc:
                tls_enc = "AES-128"

        if 'CBC' in ciphersuite:
            tls_cmode = "CBC"
        elif 'GCM' in ciphersuite:
            tls_cmode = "GCM"
        elif 'RC4' in ciphersuite:
            tls_cmode = "RC4"
        else:
            tls_cmode = "CBC"
                
        ## Cert params
        server_certificate_pem = server_certificate['pem']
        cert_version = server_certificate['version']
        cert_serial_hex = hex(server_certificate['serial'])[2:]
        cert_serial = ':'.join(cert_serial_hex[i:i+2] for i in range(0, len(cert_serial_hex), 2))
        cert_sigAlgo = server_certificate['algo']
        ## Cert params: issuer
        cert_issuer = server_certificate['issuer']
        cert_issuer_cn = "Unknown"
        cn_regex = ".*CN=(.*)"
        prog = re.compile(cn_regex)
        m = prog.match(server_certificate['issuer'])
        if m:
            cert_issuer_cn = m.group(1)
        ## Cert params: validity
        cert_validity = server_certificate['validity']
        cert_datevalidity_timeleft = cert_validity[1] - datetime.now()
        cert_validity.append(cert_datevalidity_timeleft)
        ## Cert params: subject
        cert_subject = server_certificate['subject']



        ## Cert Pubkey
        cert_pubkey_size = server_certificate['pubkey'][1]
        cert_pubkey_data = server_certificate['pubkey'][2]
        cert_pubkey_data_name = "Public Key Data"
        if server_certificate['pubkey'][0]==6:
            cert_pubkey_type = "RSA (exp: %s) (%s bit)"  % (server_certificate['pubkey'][3], cert_pubkey_size)
            cert_pubkey_data_name = "RSA Modulus"
            
        elif server_certificate['pubkey'][0]==408:
            cert_pubkey_type = "EC %s (%d bit)" % (server_certificate['pubkey'][3], cert_pubkey_size)
            cert_pubkey_data_name = "P(x,y) on Curve %s" % (server_certificate['pubkey'][3])
        else:
            cert_pubkey_type = "UNKNOWN"

        ## format pubkey in 32 byte lines
        cert_pubkey_data_formatted = ':'.join(cert_pubkey_data[i:i+2] for i in range(0, len(cert_pubkey_data), 2))
        cert_pubkey_data_formatted = '\n'.join(cert_pubkey_data_formatted[i:i+96] for i in range(0, len(cert_pubkey_data_formatted), 96))

        ## OK store this in the db

        serverdetails_for_db = models.ServerDetails.objects.create(
            server_geo = server_geo,
            server_whois = server_whois
            )

        pubkey_for_db = models.PublicKey.objects.create(
            pubkey_type = cert_pubkey_type,
            pubkey_size = cert_pubkey_size,
            pubkey_data =  cert_pubkey_data,
            pubkey_data_name = cert_pubkey_data_name
            )
        
        certificate_for_db = models.Certificate.objects.create(
            pem = server_certificate_pem,
            version = int(cert_version),
            serial = cert_serial,
            sigAlgo = cert_sigAlgo,
            issuer = cert_issuer,
            notBefore = cert_validity[0],
            notAfter = cert_validity[1],
            life_at_report = cert_validity[1] - scan_date,
            subject = cert_subject,
            ext_bc = server_certificate['bc'],
            ext_ku = server_certificate['ku'],
            ext_eku = server_certificate['eku'],
            ext_aia = server_certificate['aia'],
            ext_crl = server_certificate['crl'],
            ext_cp = server_certificate['cp'],
            ext_san = server_certificate['san'],
            ext_aki = server_certificate['aki'],
            pubkey = pubkey_for_db
            )

        session_for_db = models.Session.objects.create(
            date = scan_date,
            hostname = targethost,
            server_details = serverdetails_for_db,
            server_ip = server_ip,
            server_port = server_port,
            server_random = connection_params['server_random'],
            server_random_date = datetime.fromtimestamp(int(connection_params['server_random'][:8], 16)),
            client_random = connection_params['client_random'],
            client_random_date = datetime.fromtimestamp(int(connection_params['client_random'][:8], 16)),
            master_key = connection_params['master_key'],
            session_id = connection_params['session_id'],
            session_ticket = connection_params['session_ticket'],
            session_ticket_lifetime = connection_params['session_ticket_lifetime'],
            server_cipher = ciphersuite,
            tls_version = tls_version,
            tls_kx = tls_kx,
            tls_auth = tls_auth,
            tls_enc = tls_enc,
            tls_cmode = tls_cmode,
            tls_mac = tls_mac,
            certificate = certificate_for_db,
            server_http_response = server_http_response
            )

        
        scanresults_for_db = models.ScanResult.objects.create(
            date = datetime.utcnow(),
            openssl_ciphers = openssl_ciphers,
            openssl_version = openssl_version,
            session = session_for_db,
            requestor_ip = get_client_ip(request)
            )

        ## now we build our context_dict to build the report
        context_dict = {'google_maps_api_key' : settings.GOOGLE_MAPS_API_KEY,
                        'date' : datetime.utcnow(),
                        'scan_date' : scan_date,
                        'hostname': targethost, 'port' : targetport, 'openssl_ciphers': openssl_ciphers,
                        'openssl_version' : openssl_version,
                        ##'server_certificate': server_certificate, 
                        'server_random': connection_params['server_random'],
                        'server_random_date': datetime.fromtimestamp(int(connection_params['server_random'][:8], 16)),
                        'client_random' : connection_params['client_random'],
                        'client_random_date': datetime.fromtimestamp(int(connection_params['client_random'][:8], 16)),
                        'master_key' : connection_params['master_key'],
                        'session_id' : connection_params['session_id'],
                        'session_ticket' : connection_params['session_ticket'],
                        'session_ticket_lifetime' : connection_params['session_ticket_lifetime'],
                        'server_cipher' : ciphersuite,
                        'server_ip' : server_ip,
                        'server_port' : server_port,
                        'tls_version' : tls_version,
                        'tls_version_comment' : comments.tls_version(),
                        'tls_version_opinion' : opinions.versionOpinion( tls_version ),
                        'tls_kx' : comments.kx_html(tls_kx),
                        'tls_kx_comment' : comments.kx(),
                        'tls_kx_opinion' : opinions.kxOpinion(tls_kx),
                        'tls_auth' : comments.auth_html(tls_auth),
                        'tls_auth_comment' : comments.auth(),
                        'tls_auth_opinion' : opinions.authOpinion(tls_auth),
                        'tls_enc' : comments.enc_html(tls_enc),
                        'tls_enc_comment' : comments.enc(),
                        'tls_enc_opinion' : opinions.encOpinion(tls_enc),
                        'tls_cmode' : comments.cmode_html(tls_cmode),
                        'tls_cmode_comment' : comments.cmode(),
                        'tls_cmode_opinion' : opinions.cmodeOpinion(tls_cmode),
                        'tls_mac' : comments.mac_html(tls_mac),
                        'tls_mac_comment' : comments.mac(),
                        'tls_mac_opinion' : opinions.macOpinion(tls_mac),
                        'report_server_certificate_style' : opinions.certificate_style(server_certificate),
                        'report_server_certificate_image' : opinions.certificate_image(server_certificate),
                        'server_certificate_pem': server_certificate_pem,
                        'cert_version' : cert_version,
                        'cert_serial' : cert_serial,
                        'cert_sigAlgo' : cert_sigAlgo,
                        'cert_issuer' : cert_issuer.replace(",","\n"),
                        'cert_issuer_cn' : cert_issuer_cn,
                        'cert_subject' : cert_subject.replace(",","\n"),
                        'cert_notBefore' : cert_validity[0],
                        'cert_notAfter' : cert_validity[1],
                        'cert_dateValidityTime' : cert_validity[2],
                        'cert_pubkey_type' : cert_pubkey_type,
                        'cert_pubkey_size' : cert_pubkey_size,
                        'cert_pubkey_data' : cert_pubkey_data_formatted,
                        'cert_pubkey_data_color_html' : opinions.pubkey_color(cert_pubkey_data),
                        'cert_pubkey_data_name' : cert_pubkey_data_name,
                        ## Cert Ext x509v3
                        'cert_san' : server_certificate['san'],
                        'cert_bc' : server_certificate['bc'],
                        'cert_ku'  : server_certificate['ku'],
                        'cert_eku' : server_certificate['eku'],
                        'cert_aki' : server_certificate['aki'],
                        'cert_aia' : server_certificate['aia'],
                        'cert_crl' : server_certificate['crl'],
                        'cert_cp'  : server_certificate['cp'],
                        'server_geo' : server_geo,
                        'server_whois' : server_whois,
                        }

        return render(request, 'do.html', context_dict)
    
def about(request):
    return render(request, 'about.html')

def restricted(request):
    return render(request, 'about.html')

def submitscan(request):
    if request.method == 'POST':
        hostname = request.POST.get('hostname')
        port = request.POST.get('port')
        if (hostname != '' and port != ''):
            return HttpResponseRedirect("report/%s/%s" % (hostname, port))
    return HttpResponseRedirect("/scan")

def user_login(request):
    # Like before, obtain the context for the user's request.
    context = RequestContext(request)

    # If the request is a HTTP POST, try to pull out the relevant information.
    if request.method == 'POST':
        # Gather the username and password provided by the user.
        # This information is obtained from the login form.
        username = request.POST['username']
        password = request.POST['password']

        # Use Django's machinery to attempt to see if the username/password
        # combination is valid - a User object is returned if it is.
        user = authenticate(username=username, password=password)

        # If we have a User object, the details are correct.
        # If None (Python's way of representing the absence of a value), no user
        # with matching credentials was found.
        if user:
            # Is the account active? It could have been disabled.
            if user.is_active:
                # If the account is valid and active, we can log the user in.
                # We'll send the user back to the homepage.
                login(request, user)
                return HttpResponseRedirect('/')
            else:
                # An inactive account was used - no logging in!
                return HttpResponse("Your TLS Second Opinion account is disabled.")
        else:
            # Bad login details were provided. So we can't log the user in.
            print("Invalid login details: {0}, {1}".format(username, password))
            return HttpResponse("Invalid login details supplied.")

    # The request is not a HTTP POST, so display the login form.
    # This scenario would most likely be a HTTP GET.
    else:
        # No context variables to pass to the template system, hence the
        # blank dictionary object...
        return render_to_response('login.html', {}, context)
    
def register(request):
    # A boolean value for telling the template whether the registration was successful.
    # Set to False initially. Code changes value to True when registration succeeds.
    registered = False

    # If it's a HTTP POST, we're interested in processing form data.
    if request.method == 'POST':
        # Attempt to grab information from the raw form information.
        # Note that we make use of both UserForm and UserProfileForm.
        user_form = UserForm(data=request.POST)
        profile_form = UserProfileForm(data=request.POST)

        # If the two forms are valid...
        if user_form.is_valid() and profile_form.is_valid():
            # Save the user's form data to the database.
            user = user_form.save()

            # Now we hash the password with the set_password method.
            # Once hashed, we can update the user object.
            user.set_password(user.password)
            user.save()

            # Now sort out the UserProfile instance.
            # Since we need to set the user attribute ourselves, we set commit=False.
            # This delays saving the model until we're ready to avoid integrity problems.
            profile = profile_form.save(commit=False)
            profile.user = user

            # Did the user provide a profile picture?
            # If so, we need to get it from the input form and put it in the UserProfile model.
            if 'picture' in request.FILES:
                profile.picture = request.FILES['picture']

            # Now we save the UserProfile model instance.
            profile.save()

            # Update our variable to tell the template registration was successful.
            registered = True

        # Invalid form or forms - mistakes or something else?
        # Print problems to the terminal.
        # They'll also be shown to the user.
        else:
            print("%s %s" % (user_form.errors, profile_form.errors))

    # Not a HTTP POST, so we render our form using two ModelForm instances.
    # These forms will be blank, ready for user input.
    else:
        user_form = UserForm()
        profile_form = UserProfileForm()

    # Render the template depending on the context.
    return render(request,
            'register.html',
            {'user_form': user_form, 'profile_form': profile_form, 'registered': registered} )

def user_logout(request):
    # Since we know the user is logged in, we can now just log them out.
    logout(request)

    # Take the user back to the homepage.
    return HttpResponseRedirect('/')

def handler404(request):
    response = render_to_response('404.html', {},
                                  context_instance=RequestContext(request))
    response.status_code = 404
    return response

def handler500(request):
    response = render_to_response('500.html', {},
                                  context_instance=RequestContext(request))
    response.status_code = 500
    return response
