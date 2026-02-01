from .carbonblack import CarbonBlackBackend
from importlib.metadata import version, PackageNotFoundError
# TODO: add all backend classes that should be exposed to the user of your backend in the import statement above.

backends = {        # Mapping between backend identifiers and classes. This is used by the pySigma plugin system to recognize backends and expose them with the identifier.
    "carbonblack": CarbonBlackBackend,
}

try:
    __version__ = version("pySigma-backend-carbonblack")
except PackageNotFoundError:
    __version__ = "0.0.0"