import os
import sys

# Crear la estructura del proyecto
base_path = r'c:\dev\key_exchange'
os.makedirs(f'{base_path}\\key_exchange', exist_ok=True)

# Crear requirements.txt
with open(f'{base_path}\\requirements.txt', 'w') as f:
    f.write('cryptography\npsec\ndukpt\n')

# Crear .gitignore
gitignore_content = '''# Virtual environment
.venv/
venv/
ENV/
env/

# Python cache
__pycache__/
*.py[cod]
*$py.class
*.so

# Cryptographic files
*.bin
*.key
*.pem
*.crt
*.csr

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Distribution
build/
dist/
*.egg-info/

# Testing
.pytest_cache/
.coverage
htmlcov/

# OS
.DS_Store
Thumbs.db
'''
with open(f'{base_path}\\.gitignore', 'w') as f:
    f.write(gitignore_content)

# Crear README.md
readme_content = '''# KMS Key Exchange Tool

A professional cryptographic key exchange and management tool.

## Features

- Secure key exchange mechanisms
- DUKPT support
- Command-line interface for key operations

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python -m key_exchange --help
```
'''
with open(f'{base_path}\\README.md', 'w') as f:
    f.write(readme_content)

# Crear __init__.py
with open(f'{base_path}\\key_exchange\\__init__.py', 'w') as f:
    f.write('')

# Crear core.py
core_content = '''"""
Core cryptographic logic for key exchange operations.
"""


class KeyExchange:
    """Handle cryptographic key exchange operations."""
    
    def __init__(self):
        pass
'''
with open(f'{base_path}\\key_exchange\\core.py', 'w') as f:
    f.write(core_content)

# Crear cli.py
cli_content = '''"""
Command-line interface for key exchange operations.
"""
import argparse


def create_parser():
    """Create and return the argument parser."""
    parser = argparse.ArgumentParser(
        description='KMS Key Exchange Tool',
        prog='key_exchange'
    )
    
    return parser


def main(args=None):
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args(args)
'''
with open(f'{base_path}\\key_exchange\\cli.py', 'w') as f:
    f.write(cli_content)

# Crear __main__.py
main_content = '''"""
Entry point for the key_exchange package.
"""
from key_exchange.cli import main

if __name__ == '__main__':
    main()
'''
with open(f'{base_path}\\key_exchange\\__main__.py', 'w') as f:
    f.write(main_content)

print('✓ Proyecto key_exchange creado exitosamente')
print('✓ requirements.txt')
print('✓ .gitignore')
print('✓ README.md')
print('✓ key_exchange/__init__.py')
print('✓ key_exchange/core.py')
print('✓ key_exchange/cli.py')
print('✓ key_exchange/__main__.py')
