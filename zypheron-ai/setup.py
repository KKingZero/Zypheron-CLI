from pathlib import Path
from setuptools import find_packages, setup


def read_requirements(filename: str) -> list[str]:
    path = Path(__file__).parent / filename
    if not path.exists():
        return []

    requirements: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        requirements.append(line)
    return requirements


core_requirements = read_requirements("requirements.txt")

extras = {
    "ml": read_requirements("requirements-ml.txt"),
    "security": read_requirements("requirements-security.txt"),
    "web": read_requirements("requirements-web.txt"),
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
        "uv>=0.2.0",
        "pip-tools>=7.4.0",
    ],
}

extras["all"] = sorted({pkg for key in ("ml", "security", "web") for pkg in extras[key]})

setup(
    name="zypheron-ai",
    version="1.0.0",
    description="Zypheron AI Engine - Advanced AI-Powered Penetration Testing",
    author="Zypheron Team",
    author_email="team@zypheron.io",
    packages=find_packages(),
    install_requires=core_requirements,
    python_requires=">=3.11,<3.13",
    extras_require=extras,
    entry_points={
        "console_scripts": [
            "zypheron-ai=core.server:main",
        ],
    },
)

