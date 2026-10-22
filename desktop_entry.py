"""Portable entrypoint: do not import any macOS-only modules on an unsupported OS."""
import sys

from platform_contract import describe
from platform_adapters import select_backend


def main(arguments=None):
    info = describe()
    return select_backend(info).run(arguments)


if __name__ == "__main__":
    sys.exit(main())
