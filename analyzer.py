"""
AuthSentinel (Legacy analyzer.py entry point).
This wrapper preserves compatibility with the original 'python analyzer.py <file>' syntax
while leveraging the advanced AuthSentinel correlation and threat detection engine.
"""

import sys
from cli import main

if __name__ == "__main__":
    main()
