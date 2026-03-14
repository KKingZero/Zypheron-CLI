"""Entry point for running zypheron-ai as a module"""
import asyncio
from core.server import main

if __name__ == '__main__':
    asyncio.run(main())
