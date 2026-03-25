"""CLI tests that invoke the erc7730 command as a subprocess."""

import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from eth_abi import encode

from erc7730._abi import compute_selector

REGISTRY_PATH = Path(__file__).parent.parent.parent / "clear-signing-erc7730-registry"

USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
AAVE_POOL = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"
SAFE_1_4_1 = "0x41675C099F32341bf84BFc5382aF534df5C7461a"
MULTISEND = "0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526"
USER = "0x9467919138E36f0252886519f34a0f8016dDb3a3"
ZERO = "0x0000000000000000000000000000000000000000"
UNISWAP_ROUTER = "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD"


@pytest.fixture()
def registry_available() -> Path:
    if not REGISTRY_PATH.exists():
        pytest.skip("Local registry not available")
    return REGISTRY_PATH


def _run_cli(*args: str, expect_error: bool = False) -> subprocess.CompletedProcess:
    result = subprocess.run(
        [sys.executable, "-m", "erc7730", *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if not expect_error:
        assert result.returncode == 0, f"CLI failed: {result.stderr}"
    return result


# ── Calldata builders ────────────────────────────────────────────────────────


def _erc20_approve_calldata(spender: str, amount: int) -> bytes:
    sel = compute_selector("approve", ["address", "uint256"])
    return sel + encode(["address", "uint256"], [spender, amount])


def _aave_supply_calldata(asset: str, amount: int, on_behalf_of: str) -> bytes:
    sel = compute_selector("supply", ["address", "uint256", "address", "uint16"])
    return sel + encode(
        ["address", "uint256", "address", "uint16"],
        [asset, amount, on_behalf_of, 0],
    )


def _safe_exec_calldata(
    to: str, inner: bytes, operation: int = 0, from_addr: str | None = None,
) -> str:
    sel = compute_selector("execTransaction", [
        "address", "uint256", "bytes", "uint8",
        "uint256", "uint256", "uint256",
        "address", "address", "bytes",
    ])
    params = encode(
        ["address", "uint256", "bytes", "uint8",
         "uint256", "uint256", "uint256",
         "address", "address", "bytes"],
        [to, 0, inner, operation, 0, 0, 0, ZERO, ZERO, b""],
    )
    return "0x" + sel.hex() + params.hex()


def _pack_multisend_tx(op: int, to: str, value: int, data: bytes) -> bytes:
    to_bytes = bytes.fromhex(to[2:])
    return (
        struct.pack("B", op)
        + to_bytes
        + value.to_bytes(32, "big")
        + len(data).to_bytes(32, "big")
        + data
    )


# ── README example tests ────────────────────────────────────────────────────


class TestSafeApproveExample:
    """Safe execTransaction wrapping an ERC-20 approve."""

    def test_decodes_outer_safe_layer(self, registry_available: Path):
        inner = _erc20_approve_calldata(AAVE_POOL, 1_000_000)
        calldata = _safe_exec_calldata(USDC, inner)

        result = _run_cli(
            "translate", calldata,
            "--to", SAFE_1_4_1,
            "--registry-path", str(registry_available),
            "--from-address", USER,
        )
        assert "Intent: sign multisig operation" in result.stdout
        assert "Operation type: Call" in result.stdout
        assert f"From Safe: {SAFE_1_4_1}" in result.stdout
        assert f"Execution signer: {USER}" in result.stdout

    def test_recursively_decodes_inner_approve(self, registry_available: Path):
        inner = _erc20_approve_calldata(AAVE_POOL, 1_000_000)
        calldata = _safe_exec_calldata(USDC, inner)

        result = _run_cli(
            "translate", calldata,
            "--to", SAFE_1_4_1,
            "--registry-path", str(registry_available),
            "--from-address", USER,
        )
        assert "Approve" in result.stdout
        assert "approve(address,uint256)" in result.stdout
        assert "Spender:" in result.stdout
        assert "Amount: 1000000" in result.stdout

    def test_json_output(self, registry_available: Path):
        inner = _erc20_approve_calldata(AAVE_POOL, 1_000_000)
        calldata = _safe_exec_calldata(USDC, inner)

        result = _run_cli(
            "translate", calldata,
            "--to", SAFE_1_4_1,
            "--registry-path", str(registry_available),
            "--from-address", USER,
            "--json",
        )
        data = json.loads(result.stdout)
        assert data["intent"] == "sign multisig operation"
        assert data["entity"] == "Safe"
        tx_field = next(f for f in data["fields"] if f["label"] == "Transaction")
        assert "Approve" in tx_field["value"]


class TestSafeAaveSupplyExample:
    """Safe execTransaction wrapping an Aave v3 supply."""

    def test_decodes_nested_supply(self, registry_available: Path):
        inner = _aave_supply_calldata(USDC, 1_000_000, USER)
        calldata = _safe_exec_calldata(AAVE_POOL, inner)

        result = _run_cli(
            "translate", calldata,
            "--to", SAFE_1_4_1,
            "--registry-path", str(registry_available),
            "--from-address", USER,
        )
        assert "Intent: sign multisig operation" in result.stdout
        assert "Supply (Aave)" in result.stdout
        assert "supply(address,uint256,address,uint16)" in result.stdout
        assert "Amount to supply: 1000000" in result.stdout

    def test_json_output(self, registry_available: Path):
        inner = _aave_supply_calldata(USDC, 1_000_000, USER)
        calldata = _safe_exec_calldata(AAVE_POOL, inner)

        result = _run_cli(
            "translate", calldata,
            "--to", SAFE_1_4_1,
            "--registry-path", str(registry_available),
            "--from-address", USER,
            "--json",
        )
        data = json.loads(result.stdout)
        tx_field = next(f for f in data["fields"] if f["label"] == "Transaction")
        assert "Supply (Aave)" in tx_field["value"]
        assert "Amount to supply: 1000000" in tx_field["value"]


class TestSafeMultiSendExample:
    """Safe execTransaction via MultiSend — hits schema limits."""

    def test_outer_safe_decodes(self, registry_available: Path):
        approve_data = _erc20_approve_calldata(AAVE_POOL, 1_000_000)
        supply_data = _aave_supply_calldata(USDC, 1_000_000, USER)

        packed = (
            _pack_multisend_tx(0, USDC, 0, approve_data)
            + _pack_multisend_tx(0, AAVE_POOL, 0, supply_data)
        )
        multisend_sel = compute_selector("multiSend", ["bytes"])
        multisend_calldata = multisend_sel + encode(["bytes"], [packed])

        calldata = _safe_exec_calldata(MULTISEND, multisend_calldata, operation=1)

        result = _run_cli(
            "translate", calldata,
            "--to", SAFE_1_4_1,
            "--registry-path", str(registry_available),
            "--from-address", USER,
        )
        assert "Intent: sign multisig operation" in result.stdout
        assert "Operation type: Delegate Call" in result.stdout

    def test_multisend_inner_is_raw_hex(self, registry_available: Path):
        """MultiSend packed encoding can't be decoded by ERC-7730 schema."""
        approve_data = _erc20_approve_calldata(AAVE_POOL, 1_000_000)
        supply_data = _aave_supply_calldata(USDC, 1_000_000, USER)

        packed = (
            _pack_multisend_tx(0, USDC, 0, approve_data)
            + _pack_multisend_tx(0, AAVE_POOL, 0, supply_data)
        )
        multisend_sel = compute_selector("multiSend", ["bytes"])
        multisend_calldata = multisend_sel + encode(["bytes"], [packed])

        calldata = _safe_exec_calldata(MULTISEND, multisend_calldata, operation=1)

        result = _run_cli(
            "translate", calldata,
            "--to", SAFE_1_4_1,
            "--registry-path", str(registry_available),
            "--from-address", USER,
        )
        # The Transaction field should contain raw hex (multiSend not decoded)
        assert "Transaction: 0x8d80ff0a" in result.stdout


class TestUniswapUniversalRouterExample:
    """Uniswap Universal Router — no descriptor in registry."""

    CALLDATA = (
        "0x3593564c000000000000000000000000000000000000000000000000000000000000006"
        "000000000000000000000000000000000000000000000000000000000000000a0000000000"
        "000000000000000000000000000000000000000000000065f5e10000000000000000000000"
        "000000000000000000000000000000000000000000020b000000000000000000000000000"
        "000000000000000000000000000000000000000000000000000000000000000000000000000"
        "000000000000000000000000020000000000000000000000000000000000000000000000000"
        "000000000000004000000000000000000000000000000000000000000000000000000000000"
        "000a000000000000000000000000000000000000000000000000000000000000000400000000"
        "000000000000000000000000000000000000000000000000000000002000000000000000000"
        "000000000000000000000000000000000016345785d8a00000000000000000000000000000"
        "000000000000000000000000000000000000010000000000000000000000000000000000000"
        "00000000000000000000000000002000000000000000000000000000000000000000000000"
        "000016345785d8a0000000000000000000000000000000000000000000000000000000000"
        "0002faf08000000000000000000000000000000000000000000000000000000000000000a0"
        "000000000000000000000000000000000000000000000000000000000000000100000000000"
        "0000000000000000000000000000000000000000000000000002bc02aaa39b223fe8d0a0e5"
        "c4f27ead9083c756cc20001f4a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000"
        "0000000000000000000000000000000000"
    )

    def test_no_descriptor_found(self, registry_available: Path):
        result = _run_cli(
            "translate", self.CALLDATA,
            "--to", UNISWAP_ROUTER,
            "--chain-id", "1",
            "--registry-path", str(registry_available),
            expect_error=True,
        )
        assert result.returncode != 0
        assert "No ERC-7730 descriptor found" in result.stderr
        assert "0x3593564c" in result.stderr


# ── Original tests ───────────────────────────────────────────────────────────


class TestBasicCLI:
    def test_erc20_transfer_human_output(self, registry_available: Path):
        sel = compute_selector("transfer", ["address", "uint256"])
        params = encode(
            ["address", "uint256"],
            ["0x000000000000000000000000000000000000dEaD", 1_000_000_000_000_000_000],
        )
        calldata = "0x" + sel.hex() + params.hex()

        result = _run_cli(
            "translate", calldata,
            "--to", "0x0000000000000000000000000000000000000001",
            "--chain-id", "1",
            "--registry-path", str(registry_available),
        )
        assert "Intent: Send" in result.stdout
        assert "Function: transfer(address,uint256)" in result.stdout

    def test_erc20_transfer_json_output(self, registry_available: Path):
        sel = compute_selector("transfer", ["address", "uint256"])
        params = encode(
            ["address", "uint256"],
            ["0x000000000000000000000000000000000000dEaD", 1_000_000_000_000_000_000],
        )
        calldata = "0x" + sel.hex() + params.hex()

        result = _run_cli(
            "translate", calldata,
            "--to", "0x0000000000000000000000000000000000000001",
            "--chain-id", "1",
            "--registry-path", str(registry_available),
            "--json",
        )
        data = json.loads(result.stdout)
        assert data["intent"] == "Send"
        assert data["function_name"] == "transfer"
        assert len(data["fields"]) >= 2


class TestCLIErrors:
    def test_missing_to_flag(self):
        result = _run_cli("translate", "0xdeadbeef", expect_error=True)
        assert result.returncode != 0

    def test_unknown_selector(self, registry_available: Path):
        result = _run_cli(
            "translate", "0xdeadbeef",
            "--to", "0x0000000000000000000000000000000000000001",
            "--registry-path", str(registry_available),
            expect_error=True,
        )
        assert result.returncode != 0
        assert "No ERC-7730 descriptor found" in result.stderr

    def test_calldata_too_short(self, registry_available: Path):
        result = _run_cli(
            "translate", "0xdead",
            "--to", "0x0000000000000000000000000000000000000001",
            "--registry-path", str(registry_available),
            expect_error=True,
        )
        assert result.returncode != 0
        assert "too short" in result.stderr
