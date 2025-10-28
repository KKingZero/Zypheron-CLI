from setuptools import setup, find_packages

setup(
    name="zypheron-ai",
    version="1.0.0",
    description="Zypheron AI Engine - Advanced AI-Powered Penetration Testing",
    author="Zypheron Team",
    author_email="team@zypheron.io",
    packages=find_packages(),
    install_requires=[
        "anthropic>=0.18.0",
        "openai>=1.12.0",
        "google-generativeai>=0.3.2",
        "requests>=2.31.0",
        "numpy>=1.24.0",
        "pandas>=2.0.0",
        "scikit-learn>=1.3.0",
        "torch>=2.1.0",
        "transformers>=4.36.0",
        "python-nmap>=0.7.1",
        "nvdlib>=0.7.4",
        "networkx>=3.1",
        "pyzmq>=25.1.0",
        "python-dotenv>=1.0.0",
        "pydantic>=2.5.0",
        "pyyaml>=6.0.1",
        "colorama>=0.4.6",
        "rich>=13.7.0",
        "tenacity>=8.2.3",
        "aiohttp>=3.9.0",
        "loguru>=0.7.0",
    ],
    python_requires=">=3.9",
    extras_require={
        "test": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.12.0",
        ],
        "dev": [
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "bandit>=1.7.5",
        ],
    },
    entry_points={
        "console_scripts": [
            "zypheron-ai=core.server:main",
        ],
    },
)

