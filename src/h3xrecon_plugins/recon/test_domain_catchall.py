from typing import AsyncGenerator, Dict, Any
from h3xrecon_plugins import ReconPlugin
from h3xrecon_core import *
from loguru import logger
import asyncio
import json
import os
import dns.resolver
import random
import string

class TestDomainCatchall(ReconPlugin):
    @property
    def name(self) -> str:
        return os.path.splitext(os.path.basename(__file__))[0]
    
    def random_string(self, length=10):
        """Generate a random string of fixed length."""
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(length))
    
    def check_catchall(self, domain, resolver=None):
        """Check if a domain is a DNS catchall."""
        random_subdomain = f"{self.random_string()}.{domain}"
        try:
            resolver.resolve(random_subdomain, 'A')
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            return False
        except dns.resolver.Timeout:
            return False
        except Exception as e:
            return False

    async def execute(self, target: str, program_id: int = None, execution_id: str = None) -> AsyncGenerator[Dict[str, Any], None]:
        logger.info(f"Running {self.name} on {target}")
        
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8']  # Using Google's DNS server, you can change this if needed
        
        is_catchall = self.check_catchall(target, resolver)
        
        result = {
            "domain": target,
            "is_catchall": is_catchall
        }
        
        yield result
    
    async def process_output(self, output_msg: Dict[str, Any], db = None) -> Dict[str, Any]:
        self.config = Config()
        self.db = db
        self.qm = QueueManager(self.config.nats)
        if await self.db.check_domain_regex_match(output_msg.get('source').get('target'), output_msg.get('program_id')):
            logger.info(f"Domain {output_msg.get('source').get('target')} is part of program {output_msg.get('program_id')}. Sending to data processor.")
            msg = {
                "program_id": output_msg.get('program_id'),
                "data_type": "domain",
                "data": [output_msg.get('output', {}).get('domain')],
                "attributes": {
                    "is_catchall": output_msg.get('output', {}).get('is_catchall')
                }
            }
            await self.qm.publish_message(subject="recon.data", stream="RECON_DATA", message=msg)
        else:
            logger.info(f"Domain {output_msg.get('source').get('target')} is not part of program {output_msg.get('program_id')}. Skipping processing.")