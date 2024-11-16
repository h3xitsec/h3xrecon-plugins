from setuptools import setup, find_packages
import os
import subprocess

# Get current git branch
try:
    current_branch = subprocess.check_output(['git', 'rev-parse', '--abbrev-ref', 'HEAD']).decode('utf-8').strip()
except (subprocess.CalledProcessError, FileNotFoundError):
    current_branch = 'main'  # Fallback to main if git command fails

# Get the absolute path to the README.md file
readme_path = os.path.join(os.path.dirname(__file__), 'README.md')

# Read the README.md content
with open(readme_path, 'r', encoding='utf-8') as f:
   long_description = f.read()

setup(
    name="h3xrecon_plugins",
    version="0.0.1",
    packages=find_packages(where='src'),  # Corrected package discovery
    package_dir={'': 'src'},  # Corrected package directory
    install_requires=[
        "docopt",
        "loguru",
        "tabulate",
        "nats-py",
        "asyncpg",
        "python-dotenv",
        "redis",
        "jsondiff",
        "python-dateutil",
        "dnspython",
        f"h3xrecon-core @ git+https://github.com/h3xitsec/h3xrecon-core.git@{current_branch}"
    ],
    author="@h3xitsec",
    description="Worker plugins for h3xrecon bug bounty reconnaissance automation",
    long_description=long_description,  # Use the actual README content
    long_description_content_type="text/markdown",
    url="https://github.com/h3xitsec/h3xrecon-plugins",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
)
