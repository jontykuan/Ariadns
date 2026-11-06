from unittest.mock import MagicMock
from ariadns.interfaces.cli import build_parser, execute_doctor, execute_init, main
from ariadns.models.entities import InvestigationResult

def test_cli_parser_subcommands():
    parser = build_parser()
    args = parser.parse_args(["run", "-d", "example.com", "--depth", "2", "--no-portscan"])
    assert args.command == "run"
    assert args.domain == "example.com"
    assert args.depth == 2
    assert args.no_portscan is True

def test_cli_parser_legacy_compat():
    parser = build_parser()
    args = parser.parse_args(["-d", "example.com", "--depth", "1"])
    assert args.domain == "example.com"
    assert args.depth == 1

def test_cli_doctor():
    code = execute_doctor()
    assert code == 0

def test_cli_init():
    code = execute_init()
    assert code == 0
