
"""
Test StreamManagement connection and re-connection
"""

import os
import sys
import dbus
import servicetest

from twisted.words.xish import domish
from twisted.words.protocols.jabber import xmlstream
import twisted.internet.protocol
from twisted.internet import reactor
from twisted.python import failure

from servicetest import (Event, EventPattern, unwrap, ProxyWrapper, wrap_channel)

from gabbletest import (
    make_connection, make_stream, make_result_iq,
    TlsAuthenticator, XmppXmlStream, StreamEvent,
    disconnect_conn, acknowledge_iq)
import constants as cs

import ns
import base64
import random
import hashlib
import hmac

NS_XMPP_SM3 = 'urn:xmpp:sm:3'

class SmStream(XmppXmlStream):
    def __init__(self, ev_func, authenticator):
        super().__init__(ev_func, authenticator)
        self.sm_enabled = False
        self.rx = 0
        self.tx = 0
        self.ta = 0

    def enable(self, enable):
        self.sm_enabled = True
        enabled = domish.Element((NS_XMPP_SM3, 'enabled'))
        enabled['resume'] = 'true'
        enabled['id'] = 'averyuniquestring'
        self.send(enabled)
        self.addObserver("/r", self.smack)
        self.addObserver("/a", self.acksm)
        def rxpp(evt):
            print(evt)
            self.rx += 1
        self.addObserver("//iq", rxpp, 1)
        self.addObserver("//message", rxpp, 1)
        self.addObserver("//presence", rxpp, 1)

    def resume(self, resume):
        self.sm_enabled = True
        assert resume['previd'] == 'averyuniquestring'
        assert self.ta == int(resume['h']), [self.ta, resume['h']]
        resumed = domish.Element((NS_XMPP_SM3, 'resumed'))
        resumed['h'] = str(self.rx)
        resumed['previd'] = 'averyuniquestring'
        self.send(resumed)

    def smack(self, req):
        ack = domish.Element((NS_XMPP_SM3, 'a'))
        ack['h'] = str(self.rx)
        self.send(ack)

    def acksm(self, ack):
        self.ta = int(ack['h'])
        self.event_func(StreamEvent('stream-a', ack, self))

    def sendHeader(self):
        super().sendHeader()

        if self.authenticator.authenticated:
            self.addOnetimeObserver("//enable", self.enable)
            self.addOnetimeObserver("//resume", self.resume)

    def send(self, obj):
        super().send(obj)
        if domish.IElement.providedBy(obj) and obj.name in ('iq', 'presence', 'message') and self.sm_enabled:
            self.tx += 1

    def connectionLost(self, reason):
        super().connectionLost(reason)
        self.authenticator.__init__(self.authenticator.username, self.authenticator.password)
        self.authenticator.associateWithStream(self)

class ScramAuthenticator(TlsAuthenticator):
    """A TLS stream authenticator that is deliberately broken. It sends
    <proceed/> to the client but then do nothing, so the TLS handshake will
    not work. Useful for testing regression of bug #14341."""

    def __init__(self, username, password):
        super().__init__(username, password)
        self.username = username
        self.password = password
        self.gs2_hdr = b''
        self.cf_bare = b''
        self.server_first = b''
        self.stored_key = None
        self.server_key = None
        self._mechanisms.append('SCRAM-SHA-256-PLUS')
        self.features = { **self.features,
            ns.NS_XMPP_ROSTERVER: 'ver',
            NS_XMPP_SM3: 'sm',
        }

    def auth(self, auth):
        """
doveadm pw -s SCRAM-SHA-256 -u test -p pass
{SCRAM-SHA-256}4096,kUUWnvu6LCpRsZ2kf2ET8Q==,gxa9gYcu7AKRFeHC78hBUcmzLXF1LXd0xJVbLnUT8RY=,P1Su/6jHm9awXwS3Y2RGr56KbooOKvcO7Jw6zNTx9k8=
        """
        client_first = base64.b64decode(str(auth)).decode()
        assert client_first.startswith('n,,n=test,') \
            or client_first.startswith('p=tls-unique,,n=test,') \
            or client_first.startswith('p=tls-server-end-point,,n=test,') \
	    or client_first.startswith('p=tls-exporter,,n=test,'), client_first
        if client_first.startswith('p=tls-server-end-point'):
            self.cb_data = bytes.fromhex(self.xmlstream.transport.getHandle().get_certificate().digest(b'sha256').decode().replace(':',' '))
        elif client_first.startswith('p=tls-exporter'):
            self.cb_data = self.xmlstream.transport.getHandle().export_keying_material(b'EXPORTER-Channel-Binding',32)
        elif client_first.startswith('p=tls-unique'):
            self.cb_data = self.xmlstream.transport.getHandle().getFinished()
        else:
            self.cb_data = b''

        b,a,n,r = client_first.split(',')
        self.gs2_hdr = b.encode()+b','+a.encode()+b',' # should have trailing coma for some reason
        self.cf_bare = n.encode()+b','+r.encode()  # technically should contain m which must be empty
        rnd = random.SystemRandom()
        nonce = base64.b64encode(bytes([int(rnd.random()*255) for i in range(0,15)]))
        self.salt = b'kUUWnvu6LCpRsZ2kf2ET8Q=='
        self.stored_key = base64.b64decode(b'gxa9gYcu7AKRFeHC78hBUcmzLXF1LXd0xJVbLnUT8RY=')
        self.server_key = base64.b64decode(b'P1Su/6jHm9awXwS3Y2RGr56KbooOKvcO7Jw6zNTx9k8=')
        self.server_first = r.encode() + nonce + b',s=' + self.salt + b',i=4096'

        challenge = domish.Element((ns.NS_XMPP_SASL, 'challenge'))
        challenge.addContent(base64.b64encode(self.server_first).decode())
        self.xmlstream.send(challenge)
        self.xmlstream.addOnetimeObserver("/response", self.response)

    def response(self, response):
        client_final = base64.b64decode(str(response)).decode()
        c,r,p = client_final.split(',')

        cb_proof = "c=" + base64.b64encode(self.gs2_hdr+self.cb_data).decode()
        r_proof,_,_ = self.server_first.decode().split(',')

        cli_fin_bare = c.encode() + b',' + r.encode()
        auth_message = self.cf_bare + b',' + self.server_first + b',' + cli_fin_bare
        client_proof = base64.b64decode(p[2::].encode())
        client_sig = hmac.new(self.stored_key, auth_message, 'sha256')
        client_key = bytes([x ^ y for x,y in zip(client_sig.digest(), client_proof)])
        stored_key = hashlib.sha256(client_key).digest()

        assert cb_proof == c, [cb_proof, c]
        assert r_proof == r, [r_proof, r]
        assert stored_key == self.stored_key, [stored_key, self.stored_key]

        server_sig = hmac.new(self.server_key, auth_message, 'sha256').digest()
        content = b'v='+base64.b64encode(server_sig)
        success = domish.Element((ns.NS_XMPP_SASL, 'success'))
        success.addContent(base64.b64encode(content).decode())
        self.xmlstream.send(success)

        self.xmlstream.reset()
        self.authenticated = True

class ServerTlsChanWrapper(ProxyWrapper):
    def __init__(self, object, default=cs.CHANNEL, interfaces={
            "ServerTLSConnection" : cs.CHANNEL_TYPE_SERVER_TLS_CONNECTION}):
        ProxyWrapper.__init__(self, object, default, interfaces)

class TlsCertificateWrapper(ProxyWrapper):
    def __init__(self, object, default=cs.AUTH_TLS_CERT, interfaces={
            "TLSCertificate" : cs.AUTH_TLS_CERT}):
        ProxyWrapper.__init__(self, object, default, interfaces)

def is_server_tls_chan_event(event):
    channels = event.args[0];

    if len(channels) > 1:
        return False

    path, props = channels[0]
    return props[cs.CHANNEL_TYPE] == cs.CHANNEL_TYPE_SERVER_TLS_CONNECTION

def test(q, bus, conn, stream):
    # Connection
    conn.Connect()
    q.expect('dbus-signal', signal='StatusChanged',
            args=[cs.CONN_STATUS_CONNECTING, cs.CSR_REQUESTED])

    ev, = q.expect_many(
        EventPattern('dbus-signal', signal='NewChannels',
                     predicate=is_server_tls_chan_event))

    channels = ev.args[0]
    path, props = channels[0]

    chan = ServerTlsChanWrapper(bus.get_object(conn.bus_name, path))
    hostname = props[cs.TLS_HOSTNAME]
    certificate_path = props[cs.TLS_CERT_PATH]

    certificate = TlsCertificateWrapper(bus.get_object(conn.bus_name, certificate_path))
    certificate.TLSCertificate.Accept()

    q.expect('dbus-signal', signal='Accepted')
    chan.Close()

    q.expect('dbus-signal', signal='StatusChanged', args=[cs.CONN_STATUS_CONNECTED, cs.CSR_REQUESTED])

    event = q.expect('stream-iq', query_ns='jabber:iq:roster', iq_type='get', query_name='query')
    result = make_result_iq(stream, event.stanza)
    roster = result.firstChildElement()
    roster['ver'] = 'zero'
    contact = roster.addElement((roster.uri, 'item'))
    contact['jid'] = 'contact@localhost'
    contact['subscription'] = 'both'
    contact['name'] = 'Test Contact'
    contact_group = contact.addElement((roster.uri, 'group'))
    contact_group.addContent('Allgemeine')
    stream.send(result)

    event = q.expect('stream-iq', to=None, query_ns='vcard-temp', query_name='vCard')
    acknowledge_iq(stream, event.stanza)
    q.expect('stream-presence')

    stream.send(domish.Element((NS_XMPP_SM3, 'r')))
    event = q.expect('stream-a')

    # Catch roster contact channels first
    event = q.expect('dbus-signal', signal='NewChannels') # pub
    event = q.expect('dbus-signal', signal='NewChannels') # sub
    event = q.expect('dbus-signal', signal='NewChannels') # stor
    event = q.expect('dbus-signal', signal='NewChannels') # grp

    # Initiate the conversation
    m = domish.Element((None, 'message'))
    m['from'] = 'contact@localhost/Twisted'
    m['id'] = 'hello'
    m['type'] = 'chat'
    m.addElement('body', content='hello')
    stream.send(m)

    event = q.expect('dbus-signal', signal='NewChannels')
    path, props = event.args[0][0]
    text_chan = wrap_channel(bus.get_object(conn.bus_name, path), 'Text')
    foo_at_bar_dot_com_handle = props[cs.TARGET_HANDLE]

    # Flood back the text
    msg = [
        dbus.Dictionary({ 'message-type': 0, }, signature='sv'),
        { 'content-type': 'text/plain',
          'content': "Hear me now",
        }
    ]

    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='Lorem ipsum dolor sit amet,'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='consectetur adipiscing elit,'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='sed do eiusmod tempor incididunt'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='ut labore et dolore magna aliqua.'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))

    m.body.children.clear()
    m.body.children.append('shush')
    stream.send(m)

    msg[1]['content']='Ut enim ad minim veniam,'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='quis nostrud exercitation ullamco'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='laboris nisi ut aliquip'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='ex ea commodo consequat.'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='Duis aute irure dolor'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='in reprehenderit in voluptate'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='velit esse cillum dolore'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='eu fugiat nulla pariatur.'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))

    m.body.children.clear()
    m.body.children.append('just stop that!')
    stream.send(m)

    msg[1]['content']='Excepteur sint occaecat'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='cupidatat non proident,'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='sunt in culpa qui officia'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))
    msg[1]['content']='deserunt mollit anim id est laborum.'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))

    m.body.children.clear()
    m.body.children.append('blah blah, idiot.')
    stream.send(m)

    stream.send(domish.Element((NS_XMPP_SM3, 'r')))
    event = q.expect('stream-a')

    stream.transport.abortConnection()

    q.expect('stream-connection-lost')

    # repeat connecion sequence, now after error
    q.expect('dbus-signal', signal='StatusChanged',
            args=[cs.CONN_STATUS_CONNECTING, cs.CSR_NETWORK_ERROR])

    ev, = q.expect_many(
        EventPattern('dbus-signal', signal='NewChannels',
                     predicate=is_server_tls_chan_event))

    channels = ev.args[0]
    path, props = channels[0]

    chan = ServerTlsChanWrapper(bus.get_object(conn.bus_name, path))
    hostname = props[cs.TLS_HOSTNAME]
    certificate_path = props[cs.TLS_CERT_PATH]

    certificate = TlsCertificateWrapper(bus.get_object(conn.bus_name, certificate_path))
    certificate.TLSCertificate.Accept()

    q.expect('dbus-signal', signal='Accepted')
    chan.Close()

    q.expect('dbus-signal', signal='StatusChanged', args=[cs.CONN_STATUS_CONNECTED, cs.CSR_NONE_SPECIFIED])

    stream.send(domish.Element((NS_XMPP_SM3, 'r')))
    ev = q.expect('stream-a')
    assert int(ev.stanza['h']) == stream.tx

    msg[1]['content']='Are you still here? I am not done yet!.'
    text_chan.Messages.SendMessage(msg, dbus.UInt32(0))

    ev = q.expect('stream-message')

    disconnect_conn(q, conn, stream)

if __name__ == '__main__':
    queue = servicetest.IteratingEventQueue(None)
    queue.verbose = (
        os.environ.get('CHECK_TWISTED_VERBOSE', '') != ''
        or '-v' in sys.argv)

    bus = dbus.SessionBus()

    params = {
        'account': 'test@localhost/Resource',
        'password': 'pass',
        'resource': 'Resource',
        'server': 'localhost',
        'port': dbus.UInt32(4444),
        }
    conn, jid = make_connection(bus, queue.append, params)
    authenticator = ScramAuthenticator('test', 'pass')
    stream = make_stream(queue.append, authenticator, protocol=SmStream)

    factory = twisted.internet.protocol.Factory()
    factory.protocol = lambda:stream
    port = reactor.listenTCP(4444, factory, interface='localhost')


    bus.add_signal_receiver(
        lambda *args, **kw:
            queue.append(Event('dbus-signal',
                               path=unwrap(kw['path']),
                               signal=kw['member'], args=[unwrap(a) for a in args],
                               interface=kw['interface'])),
        None,       # signal name
        None,       # interface
        None,
        path_keyword='path',
        member_keyword='member',
        interface_keyword='interface',
        byte_arrays=True
        )

    try:
        test(queue, bus, conn, stream)
    finally:
        try:
            d = port.stopListening()
            conn.Disconnect()
        except dbus.DBusException as e:
            pass
