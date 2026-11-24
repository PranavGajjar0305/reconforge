import pytest

from reconforge.config import load_config
from reconforge.db import Database
from reconforge.scope import Scope


@pytest.fixture
def cfg(tmp_path):
    return load_config("/nonexistent.yaml", overrides={
        "database": {"url": f"sqlite:///{tmp_path}/t.db"},
        "storage": {k: str(tmp_path / k) for k in ("data_dir", "evidence_dir", "reports_dir", "backups_dir", "logs_dir")},
        "targets": [{"name": "t", "root_domains": ["example.test"], "authorization": {"confirmed": True, "reference": "test"},
                     "scope": {"ip_allow": ["127.0.0.0/8", "192.0.2.0/24"]}}],
    })


@pytest.fixture
def db(cfg):
    return Database(cfg.database_url)


@pytest.fixture
def scope():
    return Scope.from_target({"root_domains": ["example.test"], "scope": {"exclude": ["*.internal.example.test"],
                                                                          "ip_allow": ["192.0.2.0/24"]},
                              "authorization": {"confirmed": True}})
