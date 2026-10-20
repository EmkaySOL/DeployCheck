import io
import json
import logging
import stat
import zipfile

from fastapi.testclient import TestClient

from deploycheck_api.main import app

client = TestClient(app)


def make_archive(files: dict[str, str | bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def upload_archive(content: bytes, filename: str = "project.zip"):
    return client.post(
        "/api/v1/scans",
        files={"archive": (filename, content, "application/zip")},
    )


def test_health_and_scan_response_schema() -> None:
    health = client.get("/api/healthz")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}

    archive = make_archive(
        {
            ".gitignore": ".env\n.venv\nnode_modules\n",
            ".env.example": "SERVICE_URL=https://example.invalid\n",
            "app.py": 'import os\nservice_url = os.getenv("SERVICE_URL")\n',
        }
    )
    response = upload_archive(archive)

    assert response.status_code == 200
    result = response.json()
    assert {
        "scan_id",
        "archive_name",
        "scanned_at",
        "files_scanned",
        "files_skipped",
        "environment_references_checked",
        "environment_declarations_available",
        "severity_counts",
        "findings",
        "limitations",
    } == set(result)
    assert result["files_scanned"] == 3
    assert result["environment_references_checked"] == 1
    assert result["environment_declarations_available"] is True
    assert result["findings"] == []
    assert set(result["severity_counts"]) == {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }


def test_hardcoded_secret_is_redacted_from_response_and_logs(caplog) -> None:
    secret = "dck_01H8Q2V9N6mR4pT7cA3f5B8"
    filename_token = "ghp_abcdefghijklmnopqrstuvwx"
    archive = make_archive(
        {
            ".gitignore": ".env\n",
            f"src/{filename_token}.py": f'API_KEY = "{secret}"\n',
        }
    )

    with caplog.at_level(logging.INFO):
        response = upload_archive(archive, f"{filename_token}.zip")

    assert response.status_code == 200
    body = json.dumps(response.json())
    assert secret not in body
    assert filename_token not in body
    assert secret not in caplog.text
    finding = next(
        item for item in response.json()["findings"] if item["rule_id"] == "SECRET003"
    )
    assert finding["evidence"] == "API_KEY = [REDACTED]"
    assert finding["file_path"] == "src/[REDACTED].py"
    assert response.json()["archive_name"] == "[REDACTED].zip"
    assert finding["severity"] == "high"


def test_private_environment_values_are_never_returned() -> None:
    secret = "env_value_that_must_never_leave_the_scanner_9812"
    archive = make_archive(
        {
            ".gitignore": ".env\n",
            ".env": f"API_KEY={secret}\n",
        }
    )

    response = upload_archive(archive)
    body = json.dumps(response.json())

    assert response.status_code == 200
    assert secret not in body
    assert any(item["rule_id"] == "CFG002" for item in response.json()["findings"])
    assert any(item["rule_id"] == "SECRET003" for item in response.json()["findings"])


def test_missing_environment_declaration_and_blank_example_value() -> None:
    archive = make_archive(
        {
            ".gitignore": ".env\n",
            ".env.example": "LOG_LEVEL=info\nOPTIONAL_SERVICE_URL=\n",
            "app.py": 'database_url = os.getenv("DATABASE_URL")\n',
        }
    )

    response = upload_archive(archive)
    findings = response.json()["findings"]
    missing = next(item for item in findings if item["rule_id"] == "ENV001")
    blank = next(item for item in findings if item["rule_id"] == "ENV002")

    assert missing["message"].startswith("DATABASE_URL ")
    assert missing["evidence"] == "Reference to DATABASE_URL; no value is shown."
    assert blank["evidence"] == "OPTIONAL_SERVICE_URL= (blank sample value)"


def test_environment_lookups_and_placeholders_are_not_secrets() -> None:
    archive = make_archive(
        {
            ".gitignore": ".env\n",
            "settings.py": (
                'API_KEY = os.getenv("API_KEY")\n'
                'PUBLIC_KEY = "your_api_key_here"\n'
            ),
        }
    )

    response = upload_archive(archive)

    assert response.status_code == 200
    assert not any(item["rule_id"].startswith("SECRET") for item in response.json()["findings"])


def test_private_key_and_debug_findings_are_explainable_and_redacted() -> None:
    private_key_header = "-----BEGIN PRIVATE KEY-----"
    archive = make_archive(
        {
            ".gitignore": ".env\n",
            "config/key.pem": f"{private_key_header}\nsynthetic-private-data\n",
            "settings.py": "DEBUG = True\n",
        }
    )

    response = upload_archive(archive)
    findings = response.json()["findings"]

    assert response.status_code == 200
    private_key = next(item for item in findings if item["rule_id"] == "SECRET001")
    debug = next(item for item in findings if item["rule_id"] == "CFG003")
    assert private_key["severity"] == "critical"
    assert private_key["evidence"] == "[REDACTED PRIVATE KEY BLOCK]"
    assert debug["evidence"] == "A debug setting is set to true."
    assert "synthetic-private-data" not in response.text


def test_ignored_directories_and_binary_files_are_skipped() -> None:
    archive = make_archive(
        {
            ".gitignore": ".env\n",
            "node_modules/package/secrets.py": 'API_KEY = "dependency-secret-987654321"\n',
            "assets/private-key.bin": b"\x00-----BEGIN PRIVATE KEY-----\x00",
        }
    )

    response = upload_archive(archive)

    assert response.status_code == 200
    result = response.json()
    assert result["files_scanned"] == 1
    assert result["files_skipped"] == 2
    assert result["findings"] == []


def test_path_traversal_is_rejected_with_safe_error() -> None:
    archive = make_archive({"../outside.py": 'API_KEY = "never-return-this"\n'})

    response = upload_archive(archive)

    assert response.status_code == 400
    assert response.json() == {"error": "The upload is not a valid, safe ZIP archive."}
    assert "outside.py" not in response.text
    assert "never-return-this" not in response.text


def test_excessively_nested_paths_are_rejected() -> None:
    deep_path = "/".join([*(f"part{index}" for index in range(16)), "file.py"])
    archive = make_archive({deep_path: "print('static only')\n"})

    response = upload_archive(archive)

    assert response.status_code == 400
    assert response.json() == {"error": "The upload is not a valid, safe ZIP archive."}


def test_symlink_entry_is_skipped() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(".gitignore", ".env\n")
        link = zipfile.ZipInfo("src/secret.py")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "target.py")

    response = upload_archive(buffer.getvalue())

    assert response.status_code == 200
    assert response.json()["files_skipped"] == 1
    assert not any(
        item["file_path"] == "src/secret.py" for item in response.json()["findings"]
    )


def test_invalid_zip_and_missing_upload_use_generic_errors() -> None:
    invalid_zip = upload_archive(b"not a zip file")
    missing_file = client.post("/api/v1/scans")

    assert invalid_zip.status_code == 400
    assert invalid_zip.json() == {
        "error": "The upload is not a valid, safe ZIP archive."
    }
    assert missing_file.status_code == 422
    assert missing_file.json() == {"error": "Invalid scan request."}


def test_request_size_limit_rejects_chunk_before_parsing(monkeypatch) -> None:
    from deploycheck_api import main as main_module

    monkeypatch.setattr(main_module, "MAX_REQUEST_BODY_BYTES", 64)
    response = upload_archive(make_archive({".gitignore": ".env\n"}))

    assert response.status_code == 413
    assert response.json() == {"error": "Uploaded archive exceeds the 12 MB limit."}


def test_oversized_text_file_is_skipped(monkeypatch) -> None:
    from deploycheck_api import scanner

    monkeypatch.setattr(scanner, "MAX_FILE_BYTES", 8)
    archive = make_archive(
        {
            ".gitignore": ".env\n",
            "src/large.py": "x" * 32,
        }
    )

    response = upload_archive(archive)

    assert response.status_code == 200
    assert response.json()["files_skipped"] == 1
    assert response.json()["files_scanned"] == 1
