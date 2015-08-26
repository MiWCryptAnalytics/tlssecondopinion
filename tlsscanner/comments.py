def tls_version():
    return "The version of the TLS protocol used by the server.\nSSLv2:   1995\nSSLv3:   1996\nTLsv1:   1999\nTLSv1.1: 2006\nTLSv1.2: 2008\n"


def kx():
    return "Allows two peers to share a secret value over an insecure channel. \nUsing Public Key Cryptography, a message can be sent from the client to the server such that no evesdropper can understand the contents of the message even if they can see the rest of the conversation.This message is input into a Key Derivation Function (KDF) to generate the session key."

def auth():
    return "Long term public key algorithm used to identify a server or client.\nIn the Public Key Infrastructure (PKI) model, this is respresented by a certificate signed by a Certification Authority (CA). Trust that this name owns the Public Key is extended from trust of that CA. Identity is proven by having the peer sign its handshake records.\n\nThe algorithm used in the TLS session matches the Public Key type used in the certificate."

def enc():
    return "A function that takes inputs of a block (fixed size) or stream (continous) of bytes and a key.\nThis transforms the data into into something that is essentially indistinguishable from random noise. Visually this might represented as static, or snow, seen on an empty television channel. The output, the ciphertext, can be transformed back to its original form by applying the same key to its corresponding decryption function.The algorithm itself must be complex enough that it is very difficult to convert the ciphertext back into its original plaintext without the key.The encryption cipher provides confidentiality of the communications."

def cmode():
    return "The particular way in which the encryption function is applied repeatedly to a sequence of blocks.\nMore advanced modes can provide additional security to make it more difficult for an attacker to try to break the cipher. Modes including mixing sequential blocks with each other and adding a incrementing counter for each block."

def mac():
    return "The function that provides integrity that the underlying data has not been modified traveling between peers."

def kx_html(tls_kx):
    if "ECDHE" == tls_kx:
            return "Elliptic Curve Diffie-Hellman Ephemeral"
    elif "ECDH" == tls_kx:
            return "Elliptic Curve Diffie-Hellman Static"
    elif 'DHE' == tls_kx:
            return "Diffie-Hellman Ephemeral"
    elif 'DH' == tls_kx:
            return "Diffie-Hellman Static"
    else:
        return tls_kx

def auth_html(tls_auth):
    if tls_auth == "ECDSA":
        return "Elliptic Curve Digital Signature Algorithm"
    elif tls_auth == "RSA":
        return "RSA Signature"
    return tls_auth

def cmode_html(tls_cmode):
    if tls_cmode == 'CBC':
            return "Cipher Block Chaining"
    elif tls_cmode == 'GCM':
            return "Galois/Counter Mode"
    elif tls_cmode == 'RC4':
            tls_cmode = "RC4 Stream Cipher"
    return tls_cmode

def enc_html(tls_enc):
    return tls_enc

def mac_html(tls_mac):
    return tls_mac
    
