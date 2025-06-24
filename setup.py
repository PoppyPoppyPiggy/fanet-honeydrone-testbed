from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="fanet-honeydrone-testbed",
    version="1.0.0",
    author="Honeydrone Research Team",
    author_email="honeydrone@example.com",
    description="FANET 기반 허니드론 네트워크 테스트베드",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/honeydrone/fanet-testbed",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": ["pytest", "pytest-asyncio", "black", "flake8"],
    },
    entry_points={
        "console_scripts": [
            "honeydrone=src.main:main",
        ],
    },
)