from setuptools import setup, find_packages

setup(
    name="pii_detector",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "pandas",
        "numpy",
        "regex",
        "i3-anonymate @ https://github.com/isudarsan/i3-anonymate/releases/download/1/i3_anonymate-1.10.0-py3-none-any.whl"
    ],
    entry_points={
        "console_scripts": [
            "pii-detector=pii_detector.cli:main",
        ],
    },
    author="Your Name",
    author_email="your.email@example.com",
    description="A package to detect and anonymize PII in logs.",
    url="https://github.com/your-username/pii_detector",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
