"""Registry loader: reads ERC-7730 descriptor files and builds a lookup index."""

import json
from dataclasses import dataclass, field
from pathlib import Path

from erc7730._abi import _split_params as _split_signature_params
from erc7730._abi import (
    canonical_signature,
    canonical_type,
    compute_selector,
    function_selector,
    parse_display_signature,
)
from erc7730._models import FunctionFormat


@dataclass
class Registry:
    """Index of ERC-7730 descriptors for fast lookup by address+selector."""

    by_deployment: dict[tuple[int, str], list[FunctionFormat]] = field(
        default_factory=dict
    )
    by_selector: dict[bytes, list[FunctionFormat]] = field(default_factory=dict)

    @classmethod
    def load(cls) -> "Registry":
        """Load the registry from the default location or ERC7730_REGISTRY_PATH."""
        import os

        path = os.environ.get("ERC7730_REGISTRY_PATH")
        if path:
            return cls.from_path(path)

        default = Path.home() / ".erc7730" / "registry"
        if default.exists():
            return cls.from_path(default)

        raise ValueError(
            "No registry found. Run erc7730.update_registry() or "
            "'erc7730 update' to download, or set ERC7730_REGISTRY_PATH."
        )

    @classmethod
    def from_path(cls, path: str | Path) -> "Registry":
        """Load all calldata descriptors from a registry directory."""
        registry = cls()
        root = Path(path)

        registry_dir = root / "registry"
        if registry_dir.exists():
            for entity_dir in sorted(registry_dir.iterdir()):
                if not entity_dir.is_dir():
                    continue
                for f in sorted(entity_dir.iterdir()):
                    if f.suffix == ".json" and f.name.startswith("calldata-"):
                        registry._load_descriptor(f, entity_dir.name)

        ercs_dir = root / "ercs"
        if ercs_dir.exists():
            for f in sorted(ercs_dir.iterdir()):
                if f.suffix == ".json" and f.name.startswith("calldata-"):
                    registry._load_descriptor(f, None)

        return registry

    def _load_descriptor(self, path: Path, entity: str | None) -> None:
        with open(path) as f:
            descriptor = json.load(f)

        context = descriptor.get("context", {})
        contract = context.get("contract", {})
        display = descriptor.get("display", {})
        metadata = descriptor.get("metadata", {})
        formats = display.get("formats", {})

        # Handle includes by loading the common file
        includes = descriptor.get("includes")
        if includes:
            includes_path = path.parent / includes
            if includes_path.exists():
                with open(includes_path) as f:
                    common = json.load(f)
                metadata = {**common.get("metadata", {}), **metadata}
                common_formats = common.get("display", {}).get("formats", {})
                formats = {**common_formats, **formats}

        abi_entries = contract.get("abi", [])
        has_inline_abi = isinstance(abi_entries, list) and len(abi_entries) > 0

        deployments = contract.get("deployments", [])
        abi_map = self._build_abi_map(abi_entries) if has_inline_abi else {}

        for format_key, format_value in formats.items():
            func_format = self._resolve_format(
                format_key, format_value, abi_map, has_inline_abi, metadata, entity
            )
            if func_format is None:
                continue

            for dep in deployments:
                key = (dep["chainId"], dep["address"].lower())
                self.by_deployment.setdefault(key, []).append(func_format)

            if not deployments:
                self.by_selector.setdefault(func_format.selector, []).append(func_format)

    def _build_abi_map(self, abi_entries: list[dict]) -> dict[bytes, dict]:
        """Build a map of selector -> ABI entry for function entries."""
        result: dict[bytes, dict] = {}
        for entry in abi_entries:
            if entry.get("type") != "function":
                continue
            sel = function_selector(entry["name"], entry.get("inputs", []))
            result[sel] = entry
        return result

    def _resolve_format(
        self,
        format_key: str,
        format_value: dict,
        abi_map: dict[bytes, dict],
        has_inline_abi: bool,
        metadata: dict,
        entity: str | None,
    ) -> FunctionFormat | None:
        """Resolve a display format key to a FunctionFormat.

        When an inline ABI is available, matches against it. When the ABI is
        a URL (not inline), synthesizes ABI info from the display key signature.
        """
        # Format keys can be hex selectors like "0xb858183f" - requires inline ABI
        if format_key.startswith("0x") and len(format_key) == 10:
            sel = bytes.fromhex(format_key[2:])
            abi_entry = abi_map.get(sel)
            if abi_entry is None:
                return None
            return self._build_function_format(
                sel, abi_entry, format_value, metadata, entity
            )

        # Format keys are function signatures like "transfer(address,uint256)"
        # or "repay(address asset, uint256 amount, ...)"
        display_name, display_types = parse_display_signature(format_key)
        display_sel = compute_selector(display_name, display_types)

        if has_inline_abi:
            abi_entry = abi_map.get(display_sel)
            if abi_entry is None:
                for sel, entry in abi_map.items():
                    if entry["name"] == display_name:
                        abi_entry = entry
                        display_sel = sel
                        break
            if abi_entry is None:
                return None
            return self._build_function_format(
                display_sel, abi_entry, format_value, metadata, entity
            )

        # No inline ABI: synthesize from the display key signature
        return self._build_function_format_from_signature(
            display_sel, display_name, display_types, format_key,
            format_value, metadata, entity,
        )

    def _build_function_format(
        self,
        selector: bytes,
        abi_entry: dict,
        format_value: dict,
        metadata: dict,
        entity: str | None,
    ) -> FunctionFormat:
        inputs = abi_entry.get("inputs", [])
        return FunctionFormat(
            selector=selector,
            name=abi_entry["name"],
            signature=canonical_signature(abi_entry["name"], inputs),
            input_names=[inp["name"] for inp in inputs],
            input_types=[canonical_type(inp) for inp in inputs],
            display=format_value,
            metadata=metadata,
            entity=metadata.get("owner") or entity,
        )

    def _build_function_format_from_signature(
        self,
        selector: bytes,
        name: str,
        types: list[str],
        raw_key: str,
        format_value: dict,
        metadata: dict,
        entity: str | None,
    ) -> FunctionFormat:
        """Build a FunctionFormat from a parsed display key when no inline ABI is available."""
        # Extract parameter names from the raw key
        paren = raw_key.index("(")
        params_str = raw_key[paren + 1 : -1]
        input_names: list[str] = []
        if params_str.strip():
            for part in _split_signature_params(params_str):
                tokens = part.strip().split()
                # "address to" -> name is "to"; "uint256" -> name is ""
                input_names.append(tokens[1] if len(tokens) > 1 else tokens[0])

        return FunctionFormat(
            selector=selector,
            name=name,
            signature=f"{name}({','.join(types)})",
            input_names=input_names,
            input_types=types,
            display=format_value,
            metadata=metadata,
            entity=metadata.get("owner") or entity,
        )

    def lookup(
        self,
        selector: bytes,
        chain_id: int,
        to: str | None = None,
    ) -> FunctionFormat | None:
        """Find a FunctionFormat matching the given selector and context.

        Tries exact (chain_id, address) match first, then falls back to
        generic descriptors (ERC standards without specific deployments).
        """
        if to:
            key = (chain_id, to.lower())
            for func in self.by_deployment.get(key, []):
                if func.selector == selector:
                    return func

        generics = self.by_selector.get(selector, [])
        if generics:
            return generics[0]

        return None
