import OpenSSL
import socket

def main():
    ## little known fact in 2015 - instagram are the only alexa topsite that enforces \r\n as line delimiter in HTTP!
    host = "instagram.com"
    ctx = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
    rawsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = OpenSSL.SSL.Connection(ctx, rawsocket)
    sock.set_tlsext_host_name(host.encode('utf-8'))

    try:
        print("connecting to %s" % host)
        sock.connect((host, 443))
    except Exception as inst:
        return "Connection Error: %s" % inst
    server_ip = sock._socket.getpeername()
    rawsocket.settimeout(None)
    try:
        sock.do_handshake()
    except Exception as inst:
        return "Handshake Error: %s" % inst
    servercert = sock.get_peer_certificate()
    print(servercert)
    print("done")
    sock.shutdown()


if __name__ == "__main__":
    main()
