import time

from dnslib.server import DNSServer, DNSLogger
from dnslib.dns import RR, A, TXT, DNSRecord, QTYPE


class Resolver:

    def __init__(self, A_answer: str, TXT_answer: str, ttl = 300):
        self.A_answer = A_answer
        self.TXT_answer = TXT_answer
        self.ttl = ttl

    def resolve(self, request: DNSRecord, handler):
        qname = request.q.qname
        qtype = request.q.qtype
        reply = request.reply()
        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, ttl=self.ttl,  rdata=A(self.A_answer)))
        elif qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, ttl=self.ttl, rdata=TXT(self.TXT_answer)))

        return reply


def create_dns_server(address: str, port: int, A_answer: str, TXT_answer: str) -> DNSServer:
    return DNSServer(
        resolver=Resolver(A_answer, TXT_answer),
        port=port,
        address=address,
        logger=DNSLogger(prefix=False)
    )



