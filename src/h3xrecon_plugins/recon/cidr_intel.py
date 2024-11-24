from typing import AsyncGenerator, Dict, Any
from h3xrecon_plugins import ReconPlugin
from h3xrecon_core import *
from loguru import logger
import asyncio
import json
import os

class CIDRIntel(ReconPlugin):
    @property
    def name(self) -> str:
        return os.path.splitext(os.path.basename(__file__))[0]

    async def execute(self, target: str, program_id: int = None, execution_id: str = None, ) -> AsyncGenerator[Dict[str, Any], None]:
        logger.info(f"Running {self.name} on {target}")
        command = f"amass intel -active -cidr {target} -ipv4"
        logger.debug(f"Running command: {command}")
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            shell=True
        )
        
        async for output in self._read_subprocess_output(process):
            try:
                json_data = {
                    "domain": output.split(" ")[0],
                    "ip": output.split(" ")[1]
                }
                logger.debug(f"Output: {json_data}")
                yield json_data
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON output: {e}")

        await process.wait()

    async def process_output(self, output_msg: Dict[str, Any], db = None) -> Dict[str, Any]:
        self.config = Config()
        self.db = db #DatabaseManager(self.config.database.to_dict())
        self.qm = QueueManager(self.config.nats)
        try:
            domain = output_msg.get('domain')
            ip = output_msg.get('ip')
            if await self.db.check_domain_regex_match(domain, output_msg.get('program_id')):
                if isinstance(ip, str):
                    try:
                        ip_message = {
                            "program_id": output_msg.get('program_id'),
                            "data_type": "ip",
                            "data": [ip],
                            "in_scope": output_msg.get('in_scope')
                        }
                        await self.qm.publish_message(subject="recon.data", stream="RECON_DATA", message=ip_message)
                        logger.debug(f"Sent IP {ip} to data processor queue for domain {output_msg.get('source').get('target')}")
                    except Exception as e:
                        logger.error(f"Error processing IP {ip}: {str(e)}")
                else:
                    logger.warning(f"Unexpected IP format: {ip}")
                domain_message = {
                    "program_id": output_msg.get('program_id'),
                    "data_type": "domain",
                    "data": [domain],
                    "in_scope": output_msg.get('in_scope')
                }
                await self.qm.publish_message(subject="recon.data", stream="RECON_DATA", message=domain_message)
                logger.debug(f"Sent domain {domain} to data processor queue for domain {output_msg.get('source').get('target')}")
            else:
                logger.info(f"Domain {domain} is not part of program {output_msg.get('program_id')}. Skipping processing.")
        except Exception as e:
            logger.error(f"Error in process_resolved_domain: {str(e)}")
            logger.exception(e)