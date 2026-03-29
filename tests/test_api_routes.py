"""
test_api_routes.py
=====================
Unit tests for FastAPI routes.
"""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient


def test_root_endpoint():
    """Test root endpoint."""
    try:
        from api.main import app
    except ImportError:
        pytest.skip("FastAPI app not available")

    client = TestClient(app)
    response = client.get("/")

    assert response.status_code == 200
    data = response.json()
    assert "name" in data
    assert data["name"] == "Ransomware Detector API"


def test_ping_endpoint():
    """Test /ping endpoint."""
    try:
        from api.main import app
    except ImportError:
        pytest.skip("FastAPI app not available")

    client = TestClient(app)
    response = client.get("/ping")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "timestamp" in data


def test_status_endpoint_requires_auth():
    """Test that /status requires authentication."""
    try:
        from api.main import app
    except ImportError:
        pytest.skip("FastAPI app not available")

    client = TestClient(app)
    response = client.get("/api/v1/status")

    assert response.status_code == 401  # Unauthorized


def test_health_endpoint_requires_auth():
    """Test that /health requires authentication."""
    try:
        from api.main import app
    except ImportError:
        pytest.skip("FastAPI app not available")

    client = TestClient(app)
    response = client.get("/api/v1/health")

    assert response.status_code == 401


def test_login_endpoint_exists():
    """Test that login endpoint exists."""
    try:
        from api.main import app
    except ImportError:
        pytest.skip("FastAPI app not available")

    client = TestClient(app)

    # Wrong credentials
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "wrong", "password": "wrong"}
    )
    assert response.status_code == 401

    # Correct credentials (default users)
    response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "ransomware_detector_admin"}
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["role"] == "admin"


def test_auth_me_endpoint(temp_dir):
    """Test /auth/me endpoint."""
    try:
        from api.main import app
    except ImportError:
        pytest.skip("FastAPI app not available")

    client = TestClient(app)

    # Login
    login_response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "ransomware_detector_admin"}
    )
    token = login_response.json()["access_token"]

    # Get current user
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["role"] == "admin"


def test_scan_hash_endpoint_requires_auth():
    """Test that /scan/hash requires authentication."""
    try:
        from api.main import app
    except ImportError:
        pytest.skip("FastAPI app not available")

    client = TestClient(app)
    response = client.post(
        "/api/v1/scan/hash",
        json={"sha256": "a" * 64}
    )
    assert response.status_code == 401


def test_honeypots_endpoint_requires_auth():
    """Test that honeypots endpoints require authentication."""
    try:
        from api.main import app
    except ImportError:
        pytest.skip("FastAPI app not available")

    client = TestClient(app)
    response = client.get("/api/v1/honeypots")
    assert response.status_code == 401


def test_report_generation_requires_auth():
    """Test that report generation requires authentication."""
    try:
        from api.main import app
    except ImportError:
        pytest.skip("FastAPI app not available")

    client = TestClient(app)
    response = client.post(
        "/api/v1/reports/generate",
        json={"format": "json"}
    )
    assert response.status_code == 401


def test_scan_hash_invalid_hash():
    """Test scan/hash with invalid hash."""
    try:
        from api.main import app
    except ImportError:
        pytest.skip("FastAPI app not available")

    client = TestClient(app)

    # Login
    login_response = client.post(
        "/api/v1/auth/token",
        data={"username": "admin", "password": "ransomware_detector_admin"}
    )
    token = login_response.json()["access_token"]

    # Invalid hash (too short)
    response = client.post(
        "/api/v1/scan/hash",
        headers={"Authorization": f"Bearer {token}"},
        json={"sha256": "abc123"}
    )
    assert response.status_code == 422  # Validation error


def test_api_schemas_validation():
    """Test Pydantic schema validation."""
    from api.schemas import ScanHashRequest

    # Valid request
    req = ScanHashRequest(sha256="a" * 64)
    assert len(req.sha256) == 64

    # Invalid (too short)
    with pytest.raises(Exception):  # ValidationError
        ScanHashRequest(sha256="abc")


def test_office_scan_response_schema():
    """Test OfficeScanResponse schema."""
    from api.schemas import OfficeScanResponse

    response = OfficeScanResponse(
        total_files=10,
        threats_found=2,
        malicious_count=1,
        suspicious_count=1,
        clean_count=8,
        results=[],
    )

    assert response.total_files == 10
    assert response.malicious_count == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
