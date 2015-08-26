import OpenSSL
import pyasn1
import pyasn1_modules
from pyasn1 import debug
from pyasn1.codec.der import decoder
from pyasn1.type import univ
from pyasn1_modules import rfc2459
import ctypes
from OpenSSL import SSL
import sys, os, select, socket
import binascii
from cryptography.hazmat.bindings.openssl.binding import Binding
import datetime
import time
import re
import ipaddress
from geolite2 import geolite2
import pprint
from collections import OrderedDict
#debug.setLogger(debug.Debug('all'))

binding = Binding()
ffi = binding.ffi
lib = binding.lib

def dump(obj):
  for attr in dir(obj):
    print("obj.%s = %s" % (attr, getattr(obj, attr)))

def X509Name_to_str(x509name):
    returnstring = ""
    for pair in x509name.get_components():
        returnstring +="%s=%s, " % (pair[0].decode(), pair[1].decode())
    ## slice extra ", "
    return returnstring[:-2]

def vanillaConnect(host, port=443, attempt_protocol=OpenSSL.SSL.SSLv23_METHOD):
    """
    Return a list of connection parameters negotiated with a vanilla connect
    :return: clientCiphers, certificate, connection params, (host,port), openssl_version
    """
    
    returnlist = []
    if ":" in host:
        host, port = host.split(":")
        port = int(port)
    else:
        host = host

    ## time before we started connection
    scan_time = datetime.datetime.utcnow()

    ## configure SSL context
    ctx = SSL.Context(attempt_protocol)
    ##ctx.set_options(SSL.OP_NO_SSLv2)
    ##ctx.set_verify(SSL.VERIFY_FAIL_IF_NO_PEER_CER6T, verify_cb) # Demand a certificate
    ##ctx.set_verify(SSL.VERIFY_PEER|SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb) # Demand a certificate
    ##ctx.use_privatekey_file (os.path.join(dir, 'server.pkey'))
    ##ctx.use_certificate_file(os.path.join(dir, 'server.cert'))
    ##ctx.load_verify_locations("server.crt")
    ##print("%s" % OpenSSL.crypto.get_elliptic_curves())
    rawsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rawsocket.settimeout(5)
    sock = SSL.Connection(ctx, rawsocket)
    sock.set_tlsext_host_name(host.encode('utf-8'))
    
    try:
        sock.connect((host, port))
    except Exception as inst:
        return "Connection Error: %s" % inst
    server_ip = sock._socket.getpeername()
    rawsocket.settimeout(None)
    try:
        sock.do_handshake()
    except Exception as inst:
        return "Handshake Error: %s" % inst
      
    returnlist.append((scan_time, sock.get_cipher_list()))
        
    servercert = sock.get_peer_certificate()
    servercert_serial = servercert.get_serial_number()
    servercert_subject = X509Name_to_str(servercert.get_subject())
    servercert_issuer = X509Name_to_str(servercert.get_issuer())
    servercert_version = servercert.get_version()
    servercert_algo = servercert.get_signature_algorithm().decode()
    servercert_validity = (servercert.get_notBefore().decode(), servercert.get_notAfter().decode())
    dt_now = datetime.datetime.utcnow()
    notbefore = str(servercert_validity[0][2:14])
    notafter =  str(servercert_validity[1][2:14])
    ## this should work for UTCtime, GeneralTime is YYYY so fix this near the year 2050
    dt_notbefore = datetime.datetime(2000 + int(notbefore[0:2]), int(notbefore[2:4]), int(notbefore[4:6]), int(notbefore[6:8]), int(notbefore[8:10]), int(notbefore[10:12]))
    dt_notafter = datetime.datetime(2000 + int(notafter[0:2]), int(notafter[2:4]), int(notafter[4:6]), int(notafter[6:8]), int(notafter[8:10]), int(notafter[10:12]))
    servercert_pubkey = servercert.get_pubkey()
    evp_pkey = servercert_pubkey._pkey
    servercert_key_bits = servercert_pubkey.bits()
    returncertificate = {}
    bio = OpenSSL.crypto._new_mem_buf()
    lib.PEM_write_bio_X509(bio, servercert._x509)
    cert_pem = OpenSSL.crypto._bio_to_string(bio).decode().strip()
    returncertificate['pem'] = cert_pem
    returncertificate['version'] = (servercert_version+1)
    returncertificate['serial'] = servercert_serial
    returncertificate['algo'] = servercert_algo
    returncertificate['issuer'] = servercert_issuer
    returncertificate['validity'] = [dt_notbefore, dt_notafter]
    returncertificate['subject'] = servercert_subject
    key_type = servercert_pubkey.type()

    ## Public Key Algo Specific Extractions
    returnpublickey = []
    returnpublickey.append(key_type)
    if (key_type==408):
        ##print("   EC")
        ec_key = lib.EVP_PKEY_get1_EC_KEY(evp_pkey)
        ec_point = lib.EC_KEY_get0_public_key(ec_key)
        ec_group = lib.EC_KEY_get0_group(ec_key)
        ec_group_nid = lib.EC_GROUP_get_curve_name(ec_group)
        ec_point_conversion_form = lib.EC_KEY_get_conv_form(ec_key)
        curve_string = ffi.string(lib.OBJ_nid2sn(ec_group_nid)).decode()
        point_string = ffi.string(lib.EC_POINT_point2hex(ec_group, ec_point, ec_point_conversion_form, ffi.NULL)).decode()
        ##print("   curve: %s" % curve_string)
        ##print("   public %s" % points_string)
        ##print("   bits: %d" % servercert_key_bits)

        returnpublickey.append(servercert_key_bits)
        returnpublickey.append(point_string)
        returnpublickey.append(curve_string)
              
        #print("%s " % lib.EC_POINT_point2oct(ec_point))
        #print("%s " % lib.EVP_PKEY_print_public(evp_key))
        ##bio = OpenSSL.crypto._new_mem_buf()
        #lib.i2d_EC_PUBKEY_bio(bio, ec_key)
        #publickey_string = OpenSSL.crypto._bio_to_string(bio)
        #print(binascii.hexlify(publickey_string))
        returncertificate['pubkey'] = returnpublickey
    elif (key_type==OpenSSL.crypto.TYPE_RSA):
        #print("   type: RSA")        
        rsa_key = lib.EVP_PKEY_get1_RSA(evp_pkey)
        bio = OpenSSL.crypto._new_mem_buf()
        lib.RSA_print(bio, rsa_key, 0)
        rsabiostring = OpenSSL.crypto._bio_to_string(bio).decode()
        openssl_rsa_print_regex = "Public-Key: \((\d+) bit\)\nModulus:\n(.*)Exponent: (\d+)"
        prog = re.compile(openssl_rsa_print_regex, re.DOTALL)
        rsa_data = prog.match(rsabiostring)
        rsa_size, rsa_mod, rsa_exp = rsa_data.groups()
        rsa_mod = rsa_mod.replace(" ", "")
        rsa_mod = rsa_mod.replace(":", "")
        rsa_mod = rsa_mod.replace("\n", "")
        returnpublickey.append(rsa_size)
        returnpublickey.append(rsa_mod)
        returnpublickey.append(rsa_exp)
        returncertificate['pubkey']=returnpublickey
    else:
        return "unsupported: %s " % returncertificate

    ## SAN and ext
    server_cert_subjectaltname = ""
    server_cert_subjectaltname_list = []
    bc, cp, crl, ku, eku, aki, aia = (), (), (), (), (), (), ()
    for ext in range(0, servercert.get_extension_count()):
      ext_obj = servercert.get_extension(ext)
      ext_name = ext_obj.get_short_name()
      #print("n: %s d: %s %s" % (ext_name, ext_obj, type(ext_obj)))
      if (ext_name == b'subjectAltName'):
        ext_data =  ext_obj.get_data()
        server_cert_subjectaltname = decoder.decode(ext_data, asn1Spec=rfc2459.SubjectAltName())[0]
        for san in server_cert_subjectaltname:
          santype = san.getName()
          sancomponent = san.getComponent() 
          if isinstance(sancomponent, pyasn1.type.char.IA5String):
            sanuri = san.getComponent().asOctets().decode()
          elif isinstance(sancomponent, pyasn1_modules.rfc2459.AnotherName):
            san_other_oid = san.getComponent().getComponentByName('type-id')
            san_other_value = san.getComponent().getComponentByName('value')
            sanuri = san_other_oid.prettyPrint() + "\n" + san_other_value.prettyPrint()
          else :
            sanuri = san.getComponent().prettyPrint()
          server_cert_subjectaltname_list.append("%s:%s" % (santype, sanuri))
      elif (ext_name == b'basicConstraints'):
        bc = ext_obj
      elif (ext_name == b'keyUsage'):
        ku = ext_obj
      elif (ext_name == b'extendedKeyUsage'):
        eku = ext_obj
      elif (ext_name == b'authorityKeyIdentifier'):
        aki = ext_obj
      elif (ext_name == b'crlDistributionPoints'):
        crl = ext_obj
      elif (ext_name == b'authorityInfoAccess'):        
        aia = ext_obj
      elif (ext_name == b'certificatePolicies'):
        cp = ext_obj
    returncertificate['san'] = server_cert_subjectaltname_list
    returncertificate['bc'] = bc
    returncertificate['eku'] = eku
    returncertificate['aki'] = aki
    returncertificate['aia'] = aia
    returncertificate['crl'] = crl
    returncertificate['ku'] = ku
    returncertificate['cp'] = cp
    
    

    ## OK done with certificate dictionary items. push to return list
    returnlist.append(returncertificate)
  
    # get ServerHello technical specifics
    cipherinuse = lib.SSL_get_current_cipher(sock._ssl)
    cipherinuse_string = ffi.string(lib.SSL_CIPHER_get_name(cipherinuse)).decode()
    cipherversion = ffi.string(lib.SSL_CIPHER_get_version(cipherinuse)).decode()
    protocolversion = ffi.string(lib.SSL_get_version(sock._ssl)).decode()
    cipherdescription = ffi.string(lib.SSL_CIPHER_description(cipherinuse, ffi.NULL, 128)).decode().strip()
    serverrandom = binascii.hexlify(sock.server_random())
    clientrandom = binascii.hexlify(sock.client_random())
    masterkey = binascii.hexlify(sock.master_key()).decode()
    

    ## requires SSL_SESSION struct expanded binding in cryptography.binding
    session = sock.get_session()

    ## print out session using SSL_SESSION_print
    #bio = OpenSSL.crypto._new_mem_buf()
    #lib.SSL_SESSION_print(bio, session._session)
    #print(OpenSSL.crypto._bio_to_string(bio))
    
    ## session params
    returnsession_params = dict()
    returnsession_params['cipher'] = cipherinuse_string
    returnsession_params['tls_version'] = protocolversion
    returnsession_params['cipher_description'] = cipherdescription
    returnsession_params['server_random'] = serverrandom
    returnsession_params['client_random'] = clientrandom
    returnsession_params['master_key'] = masterkey
    sessionid_length = session._session.session_id_length
    returnsession_params['session_id'] = binascii.hexlify(ffi.buffer(session._session.session_id))
    ## are tickets supported?
    if (session._session.tlsext_tick):
      returnsession_params['session_ticket'] = binascii.hexlify(ffi.string(session._session.tlsext_tick))
      returnsession_params['session_ticket_lifetime'] = session._session.tlsext_tick_lifetime_hint
    else:
      returnsession_params['session_ticket'] = "0"
      returnsession_params['session_ticket_lifetime'] = "0"
    returnlist.append(returnsession_params)
    returnlist.append(server_ip)
    openssl_version = ffi.string(lib.SSLeay_version(0)).decode()
    #print(openssl_version )
    returnlist.append(openssl_version)

    ## Geo Data
    language = 'en'
    server_geo = OrderedDict()
    ip_to_geo = server_ip[0]
    reader = geolite2.reader()
    match = reader.get(ip_to_geo)
    if (match != None):
      if (match.get('city') != None):
        server_geo['city'] = match['city']['names'][language]
      if (match.get('subdivisions') != None):
        server_geo['subdivisions'] = match['subdivisions'][0]['names'][language]
      if (match.get('postal') != None):
        server_geo['postal'] = match['postal']['code']
      if (match.get('country') != None):
        server_geo['country'] = match['country']['names'][language]  
      if (match.get('continent') != None):
        server_geo['continent'] = match['continent']['names'][language]
      if (match.get('location') != None):
        server_geo['location'] = (match['location']['latitude'], match['location']['longitude'])
        test_geoip_resolution = float( server_geo['location'][0] )
        if (test_geoip_resolution % 1==0):
          server_geo['zoom'] = 3
        else:
          server_geo['zoom'] = 8
      if (match.get('time_zone') != None):
        server_geo['time_zone'] = match['location']['time_zone']
      if (match.get('metro_code') != None):
        server_geo['metro_code'] = match['location']['metro_code']    
      if (match.get('registered_country') != None):
        server_geo['registered_country'] = match['registered_country']['names'][language]
    returnlist.append(server_geo)
    
    ## Application data
    try:
        useragent = "TLSSecondOpinion/1.0 (+https://tls2o.com TLS Second Opinion Bot)"
        line = "GET / HTTP/1.1\r\nHost:%s\r\nAccept: */*\r\nConnection: keep-alive\r\nUser-Agent: %s\r\n\r\n" % (host, useragent)
        sock.send(line)
        server_response = sock.recv(65535).decode()
        returnlist.append(server_response)
    except SSL.Error:
        server_response = 'Connection died unexpectedly'
    sock.shutdown()
    sock.close()
    return returnlist

def verify_cb(conn, cert, errnum, depth, ok):
    #print('Got certificate: %s' % cert.get_subject())
    return ok

def main():
    
    results = vanillaConnect("microsoft.com:443")
    print("------------------------ Finished vanillaConnect ------------------------ ")
    if type(results) == str:
      print(results)
    else:
      #for r in results:
        #print(r)
        #print("--\n")
      print("Server Certificate:")
      cert = results[1]
      server_geo = results[5]
      print (cert['pem'])
      print("\tVersion: %s" % cert['version'])
      print("\tSerial: %s" % cert['serial'])
      print("\tSignature Algoritm: %s" % cert['algo'])
      print("\tIssuer: %s" % cert['issuer'])
      print("\tValidity: between %s and %s" % (cert['validity'][0], cert['validity'][1]))
      print("\tSubject: %s" % cert['subject'])
      print("\tSubject Alt Name : %s " % cert['san'])
      if cert['bc']:
        print("\tBasic Constraints  : %s " % cert['bc'])
      if cert['crl']:
        print("\tCRL: %s " % cert['crl'])
      if cert['aki']:
        print("\tAuthority Key Identifier: %s " % cert['aki'])
      if cert['eku']:
        print("\tEnhanced Key Usage: %s " % cert['eku'])
      print("\tSubject Public Key (type): (%s) " % cert['pubkey'][0])
      if (cert['pubkey'][0]==408):
        print("\t\tType: EC")
        print("\t\tcurve: %s" % cert['pubkey'][2])
        print("\t\tpublic: %s" % cert['pubkey'][1])
        print("\t\tbits: %d" % cert['pubkey'][0])
      elif (cert['pubkey'][0]==OpenSSL.crypto.TYPE_RSA):
        print("\t\tType: RSA")
        print("\t\tbits: %s" % cert['pubkey'][1])
        print("\t\tmodulus: %s" % cert['pubkey'][2])
        print("\t\tencryption exponent: %s" % cert['pubkey'][3])
      print("\tSession Parameters:")
      params = results[2]
      for k,v in params.items():
        print("\t\t%s : %s" % (k, v))
      print("OpenSSL Version: %s" % results[4])
      print("GeoIP:\n")
      print(server_geo)

      print("response:")
      print("------------------------------------------------ ")
      print(results[6])
    
    
if __name__ == "__main__":
    main()
