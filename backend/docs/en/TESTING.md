# Testing

[🇷🇺 RU версия](../ru/TESTING.md)

## Running Tests

### All Tests

```bash
pytest
```

### With Code Coverage

```bash
pytest --cov --cov-report=html
```

Report will be available in directory `htmlcov/`

### With Coverage in Terminal

```bash
pytest --cov --cov-report=term-missing
```

### Specific Test

```bash
pytest storage/tests/test_models.py
pytest storage/tests/test_models.py::TestFileCreation::test_file_creation_with_required_fields
```

### With Detailed Output

```bash
pytest -v
pytest -vv
```

---

## Test Structure

### Users app

```
users/tests/
├── conftest.py           # Fixtures for all tests
├── test_auth.py          # Authentication tests
├── test_users.py         # User tests
└── test_admin_users.py   # Admin function tests
```

### Storage app

```
storage/tests/
├── conftest.py               # Fixtures
├── test_models.py            # Model tests
├── test_crud_views.py        # CRUD operation tests
├── test_public_views.py      # Public access tests
├── test_permission.py        # Permission tests
├── test_serializers.py       # Serializer tests
├── test_edge_cases.py        # Edge case tests
└── test_media_isolation.py   # File isolation tests
```

---

## Testing Configuration

Tests automatically use:
- **MD5PasswordHasher** - Fast password hashing
- **Temporary directory** for media files
- **Disabled** request rate limiting (throttling)

---

## Coverage Requirements

Minimum code coverage: **80%**

```bash
pytest --cov-fail-under=80
```

---

## CI/CD

On push to repository, automatically run:

```bash
# Linting
ruff check .
black --check .

# Tests with coverage
pytest --cov --cov-report=xml
```

---

## Debugging Tests

### Show print output

```bash
pytest -s
```

### Stop on first error

```bash
pytest -x
```

### Debug failing test

```bash
pytest --pdb
```

### View logs

```bash
pytest --log-cli-level=DEBUG
```
