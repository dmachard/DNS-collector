import unittest
import asyncio
import dns.resolver
import os
import subprocess

COLLECTOR_USER = os.getenv('COLLECTOR_USER')
if COLLECTOR_USER is None:
    COLLECTOR_USER  = "root"

my_resolver = dns.resolver.Resolver(configure=False)
my_resolver.nameservers = ['127.0.0.1']
my_resolver.port = 5553
my_resolver.timeout = 20
my_resolver.lifetime = 20

class ProcessProtocol(asyncio.SubprocessProtocol):
    def __init__(self, is_ready, is_clientresponse):
        self.is_ready = is_ready
        self.is_clientresponse = is_clientresponse
        self.transport = None
        self.proc = None

    def connection_made(self, transport):
        self.transport = transport
        self.proc = transport.get_extra_info('subprocess')

    def pipe_data_received(self, fd, data):
        print(data.decode(), end="")

        if b"receiver framestream initialized" in data:
            self.is_ready.set_result(True)
        
        if not self.is_clientresponse.done():
            if b"CLIENT_RESPONSE NOERROR" in data:
                self.is_clientresponse.set_result(True)
                self.kill()

    def kill(self):
        try:
            self.proc.kill()
        except ProcessLookupError: pass
        
def can_use_sudo():
    try:
        return subprocess.run(["sudo", "-n", "true"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    except:
        return False

def get_docker_restart_cmd():
    try:
        if subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            return ["docker", "restart", "dnsserver"]
    except:
        pass
    return ["sudo", "docker", "restart", "dnsserver"]

class TestDnstap(unittest.TestCase):
    def test_stdout_recv(self):
        """test to receive dnstap response in stdout"""
        async def run():
            loop = asyncio.get_running_loop()
            is_ready = asyncio.Future()
            is_clientresponse = asyncio.Future()

            # run collector
            print("Starting collector with current user: ", COLLECTOR_USER)
            if can_use_sudo():
                args = ( "sudo", "-u", COLLECTOR_USER, "-s", "./dnscollector", "-config", "./tests/testsdata/config_stdout_dnstapunix.yml",)
            else:
                args = ( "./dnscollector", "-config", "./tests/testsdata/config_stdout_dnstapunix.yml",)
            transport_collector, protocol_collector =  await loop.subprocess_exec(lambda: ProcessProtocol(is_ready, is_clientresponse),
                                                                                       *args, stdout=asyncio.subprocess.PIPE)

            print("Restarting DNS server container...")
            subprocess.run(get_docker_restart_cmd(), check=True)

            # Wait for Knot Resolver to be ready on port 5553
            import time
            print("Waiting for DNS server to be ready on port 5553...")
            for _ in range(30):
                try:
                    my_resolver.resolve('www.github.com', 'a')
                    print("DNS server is ready.")
                    break
                except Exception:
                    time.sleep(1.0)

            # Trigger first batch of DNS queries
            for i in range(20):
                try:
                    my_resolver.resolve('www.github.com', 'a')
                except Exception as e:
                    print("Resolv error: ", e)

            # Wait for the collector to be ready
            try:
                await asyncio.wait_for(is_ready, timeout=30.0)
            except asyncio.TimeoutError:
                protocol_collector.kill()
                transport_collector.close()
                self.fail("collector framestream timeout")

            # Trigger second batch of DNS queries
            for i in range(20):
                try:
                    my_resolver.resolve('www.github.com', 'a')
                except: pass
                
            # Wait for dnstap client response
            try:
                await asyncio.wait_for(is_clientresponse, timeout=30.0)
            except asyncio.TimeoutError:
                protocol_collector.kill()
                transport_collector.close()
                self.fail("dnstap client response expected")

            # Shutdown all
            protocol_collector.kill()
            transport_collector.close()

        asyncio.run(run())