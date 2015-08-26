


def versionOpinion(version):
    opinion = "Undefined version"
    color = "black"
    if version=="TLSv1.2":
        opinion = "Good.\n TLSv1.2 is the latest version of the TLS protocol"
        color = "green"
    elif version=="SSLv3":
        opinion = "Bad.\n SSLv3 is deprecated and has been comprehensivley broken. rfc7568 states SSLv3 MUST NOT be used. Negotiation of SSLv3 from any version of TLS MUST NOT be permitted."
        color = "red"
    elif version=="TLSv1":
        opinion = "May need additional mitigations depending on algorithm used. TLSv1.0 has some design flaws that are fixed in later versions. It is recommended to upgrade to TLSv1.2 support"
        color = "orange"
    elif version=="TLSv1.1":
        opinion = opinion = "May need additional mitigations depending on algorithm used. TLSv1.1 has some design flaws that are fixed in later versions. It is recommended to upgrade to TLSv1.2 support"
        color = "orange"
    return "<font color=%s>%s</font>" % (color, opinion)
    

def kxOpinion(kx):
    opinion = "Undefined kx"
    color = "black"
    if kx == "ECDHE":
        opinion = "Good.\n ECDHE provides Forward Secrecy (FS), a Key Exchange method that prevents previously recorded conversations from being decrypted if the server private key is compromised."
        color = "green"
    elif kx == "DHE":
        opinion = "Good.\n DHE provides Forward Secrecy (FS), a Key Exchange method that prevents previously recorded conversations from being decrypted if the server private key is compromised."
        color = "green"
    elif kx == "RSA":
        color = "orange"
        opinion = "OK.\n RSA Key Exchange uses the servers certificate public key. If the server private key is compromised, all previously recorded encrypted conversations can be decrypted."
    return "<font color=%s>%s</font>" % (color, opinion)

def authOpinion(auth):
    opinion = "Undefined auth"
    color = "black"
    if auth == "RSA":
        opinion = "Good.\n An RSA Public Key was provided on the server certificate. The server can prove its identity with an RSA signature."
        color = "green"
    elif auth == "ECDSA":
        opinion = "Good.\n An EC Public Key was provided on the server certificate. The server can prove its identity with a ECDSA signature."
        color = "green"
    return "<font color=%s>%s</font>" % (color, opinion)

def encOpinion(enc):
    opinion = "Undefined Enc"
    color = "black"
    if enc == "AES-128":
        opinion = "Good.\n AES-128 (bit) is a strong encryption cipher suitable to protect data to the SECRET level."
        color = "green"
    elif enc == "AES-256":
        opinion = "Good.\n AES-256 (bit) is a verys trong encryption cipher suitable to protect data to the TOP SECRET level."
        color = "green"
    elif enc == "RC4":
        opinion = "Bad.\n RC4 is considered broken and SHOULD NOT be used in TLS."
        color = "red"
    return "<font color=%s>%s</font>" % (color, opinion)

def cmodeOpinion(cmode):
    opinion = "Undefined cmode"
    color = "black"
    if cmode == "CBC":
        opinion = "Cipher Block Chaining has had some security issues, mostly with the padding in older versions of SSL/TLS. An attacker can mount a Padding Oracle Attack to recover plaintext."
        color = "orange"
    elif cmode == "GCM":
        opinion = "GCM Mode provides authenticated encryption with additional data. It prevents an attacker from substituting ciphertext"
        color = "green"
    elif cmode == "RC4":
        opinion = "Stream Ciphers such as RC4 should not be used with TLS"
        color = "red"
    return "<font color=%s>%s</font>" % (color, opinion)
            

def pubkey_color(cert_pubkey_data):
    ## This is preformated with \n's so we gotta translate it
    dirtychars = u':\n'
    translate_table = dict((ord(char), None) for char in dirtychars)
    cleaned = cert_pubkey_data.translate(translate_table)
    returnlist = []
    coloredlist = ["<table style=\"border-spacing: 0px\">"]
    for i in range(0, len(cleaned), 2):
        MSB = int(cleaned[i], 16)
        LSB = int(cleaned[i+1], 16)
        returnlist.append((MSB*16+LSB))
    group = lambda flat, size: [flat[i:i+size] for i in range(0,len(flat), size)]
    for line in group(returnlist, 32):
        coloredlist.append("<tr>")
        for element in line:
            coloredlist.append("<td style=\"width: 10px; line-height: 10px; padding: 0px; border-top: 0px;\"><div style=\"background-color: rgb(%d,%d, %d); font-family: monospace; font-size: small;\">%s</div></td>" % (element, 127+element//2, 255-element, hex(element)[2:]))
        coloredlist.append("</tr>")
    coloredlist.append("</table>")
    return "".join(coloredlist)


def pubkey_color_fire(cert_pubkey_data):
    ## This is preformated with \n's so we gotta translate it
    dirtychars = u':\n'
    translate_table = dict((ord(char), None) for char in dirtychars)
    cleaned = cert_pubkey_data.translate(translate_table)
    returnlist = []
    coloredlist = ["<table style=\"border-spacing: 0px\">"]
    for i in range(0, len(cleaned), 2):
        MSB = int(cleaned[i], 16)
        LSB = int(cleaned[i+1], 16)
        returnlist.append((MSB*16+LSB))
    group = lambda flat, size: [flat[i:i+size] for i in range(0,len(flat), size)]
    for line in group(returnlist, 32):
        coloredlist.append("<tr>")
        for element in line:
            divcolor = (192+(element//4), 64+(element//2), 32+(element//2), hex(element)[2:])
            coloredlist.append("<td style=\"width: 10px; line-height: 10px; padding: 0px; border-top: 0px;\"><div style=\"background-color: rgb(%d,%d, %d); font-family: monospace; font-size: small;\">%s</div></td>" % divcolor)
        coloredlist.append("</tr>")
    coloredlist.append("</table>")
    return "".join(coloredlist)

        

def macOpinion(mac):
    opinion = "Undefined MAC"
    color = "black"
    if mac == "AEAD":
        opinion = "The Authenticated Encryption Cipher Mode provides message integrity."
        color = "green"
    elif mac == "SHA256":
        opinion = "Good. \n Hash Based Message Authenticaiton Code using SHA-256. Considered strong."
        color = "green"
    elif mac == "SHA1":
        opinion = "Could be improved.\n While no known attacks exist against HMAC-SHA1, a stronger hash function like SHA256 should be used."
        color = "orange"
    elif mac == "MD5":
        opinion = "Bad. \n While no known attacks exist against HMAC-MD5, a stronger hash function like SHA256 should be used."
        color = "red"
    return "<font color=%s>%s</font>" % (color, opinion)

def certificate_style(server_certificate):
    ## Self Signed
    if (server_certificate['issuer'] == server_certificate['subject']):
        return "background: DarkGray; outline: DimGray  solid thin;"
    return "background-color: mintcream; outline: MediumSpringGreen solid thin;"

def certificate_image(server_certificate):
    if (server_certificate['issuer'] == server_certificate['subject']):
        return "/static/img/selfsigned.png"
    return "/static/img/valid.png"
