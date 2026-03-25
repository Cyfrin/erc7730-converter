"""ABI utilities: selector computation, calldata decoding, signature parsing."""

from eth_abi import decode as abi_decode
from eth_hash.auto import keccak


def canonical_type(abi_input: dict) -> str:
    """Convert an ABI input entry to its canonical type string.

    Handles simple types (address, uint256), tuple types with components,
    and array suffixes (tuple[], tuple[3]).
    """
    soltype = abi_input["type"]
    if soltype == "tuple" or soltype.startswith("tuple["):
        components = abi_input.get("components", [])
        inner = ",".join(canonical_type(c) for c in components)
        suffix = soltype[5:]
        return f"({inner}){suffix}"
    return soltype


def compute_selector(name: str, types: list[str]) -> bytes:
    """Compute the 4-byte function selector from a name and canonical types."""
    sig = f"{name}({','.join(types)})"
    return keccak(sig.encode())[:4]


def function_selector(name: str, inputs: list[dict]) -> bytes:
    """Compute the 4-byte function selector from ABI function inputs."""
    types = [canonical_type(inp) for inp in inputs]
    return compute_selector(name, types)


def canonical_signature(name: str, inputs: list[dict]) -> str:
    """Build the canonical function signature string from ABI inputs."""
    types = [canonical_type(inp) for inp in inputs]
    return f"{name}({','.join(types)})"


def decode_calldata(types: list[str], data: bytes) -> tuple:
    """Decode calldata bytes (without the 4-byte selector) using ABI types."""
    return abi_decode(types, data)


def parse_display_signature(sig: str) -> tuple[str, list[str]]:
    """Parse a display format key into (function_name, [canonical_types]).

    Handles both formats:
      - "transfer(address,uint256)"
      - "repay(address asset, uint256 amount, uint256 interestRateMode)"
    """
    paren = sig.index("(")
    name = sig[:paren]
    params_str = sig[paren + 1 : -1]
    if not params_str.strip():
        return name, []

    parts = _split_params(params_str)
    types = []
    for part in parts:
        tokens = part.strip().split()
        types.append(tokens[0])
    return name, types


def _split_params(params_str: str) -> list[str]:
    """Split parameter string on commas, respecting nested parentheses."""
    parts: list[str] = []
    depth = 0
    buf: list[str] = []
    for ch in params_str:
        if ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth -= 1
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert a hex string (with or without 0x prefix) to bytes.

    Strips all whitespace so calldata pasted with line breaks works.
    Pads odd-length hex strings with a trailing zero.
    """
    clean = "".join(hex_str.split()).removeprefix("0x").removeprefix("0X")
    if len(clean) % 2 != 0:
        clean += "0"
    return bytes.fromhex(clean)
