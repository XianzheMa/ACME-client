import time

from dnslib.server import DNSServer, DNSLogger
from dnslib.dns import RR, A, TXT, DNSRecord, QTYPE


class Resolver:

    def __init__(self, A_answer: str, domain2TXT: dict, ttl = 300):
        self.A_answer = A_answer
        self.domain2TXT = domain2TXT
        self.ttl = ttl

    def resolve(self, request: DNSRecord, handler):
        qname = request.q.qname
        qtype = request.q.qtype
        reply = request.reply()

        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, ttl=self.ttl,  rdata=A(self.A_answer)))
        elif qtype == QTYPE.TXT:
            domain = str(qname)[:-1]
            if domain in self.domain2TXT:
                for TXT_val in self.domain2TXT[domain]:
                    reply.add_answer(RR(qname, QTYPE.TXT, ttl=self.ttl, rdata=TXT(TXT_val)))
            else:
                reply.add_answer(RR(qname, QTYPE.TXT, ttl=self.ttl, rdata=TXT('None')))

        return reply


def create_dns_server(address: str, port: int, A_answer: str, domain2TXT = dict()) -> DNSServer:
    return DNSServer(
        resolver=Resolver(A_answer, domain2TXT),
        port=port,
        address=address,
        logger=DNSLogger(prefix=False)
    )



