"""认证模块测试：bcrypt 哈希往返 + JWT 签发/校验（PRD 7.2）。"""

import pytest
from fastapi import HTTPException

from app.auth import hash_password, verify_password, create_token, get_current_user
from config import CONFIG


def test_password_hash_roundtrip():
    h = hash_password("secret123")
    assert h != "secret123"
    assert verify_password("secret123", h) is True
    assert verify_password("wrong", h) is False


def test_jwt_roundtrip():
    token = create_token("admin")
    assert get_current_user(authorization=f"Bearer {token}") == "admin"


def test_jwt_requires_bearer():
    with pytest.raises(HTTPException) as e:
        get_current_user(authorization=None)
    assert e.value.status_code == 401
