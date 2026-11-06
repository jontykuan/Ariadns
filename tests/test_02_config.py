from pathlib import Path
from ariadns.models.config import AppConfig, mask_secret

def test_mask_secret():
    assert mask_secret("abcdef123456") == "abc***"
    assert mask_secret("ab") == "***"
    assert mask_secret("") == ""
    assert mask_secret(None) == ""

def test_blacklists():
    cfg = AppConfig()
    assert cfg.is_mx_blacklisted("aspmx.l.google.com") is True
    assert cfg.is_mx_blacklisted("mail.mycompany.org") is False
    assert cfg.is_ns_blacklisted("ns1.cloudflare.com.") is True
    assert cfg.is_ns_blacklisted("ns1.mycompany.org") is False

def test_load_defaults():
    cfg = AppConfig.load(Path("config.yaml.example"))
    assert cfg.virustotal_rpm == 4
    assert cfg.cache_ttl_seconds == 604800
    assert "google.com" in cfg.mx_blacklist
