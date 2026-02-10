from setuptools import setup, find_packages

setup(
    name="rootkit",
    version="2.0.0",
    author="bad-antics",
    description="Rootkit development and detection research toolkit",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=["requests", "colorama", "pyyaml", "rich"],
)
