from setuptools import setup, find_packages

setup(
    name="wordpress-security-scanner",
    version="0.1.0",
    description="Desktop application for automated WordPress security testing with report generation.",
    author="Your Name",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    install_requires=[
        "PySide6>=6.5.0",
        "requests>=2.31.0",
        "aiohttp>=3.9.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=4.9.0",
        "reportlab>=4.0.0",
        "jinja2>=3.1.0",
        "matplotlib>=3.8.0",
        "aiosqlite>=0.19.0",
        "pyopenssl>=23.0.0",
        "cryptography>=41.0.0",
    ],
    entry_points={
        "console_scripts": [
            "wpsec-scanner=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "reports": ["templates/*.html", "templates/*.css"],
    },
)