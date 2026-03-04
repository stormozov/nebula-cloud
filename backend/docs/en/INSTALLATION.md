# Installation and Setup

[🇷🇺 RU версия](../ru/INSTALLATION.md)

## Requirements

- Python 3.12.3
- PostgreSQL 18
- Git
- uv 0.10.1

## Step 1: Clone the Repository

```bash
git clone https://github.com/stormozov/nebula-cloud
cd backend
```

## Step 2: Create and Activate Virtual Environment

### Create

```bash
uv venv
```

### Activate

```powershell
# Windows (PowerShell)
.venv\Scripts\activate

# Windows (Bash)
source .venv/Scripts/activate

# Linux/Mac
source .venv/bin/activate
```

> **Note:** Ensure the virtual environment is activated (there should be a prefix in the command line).

## Step 3: Install Dependencies

```bash
uv pip install -e ".[dev]"
```

## Step 4: Database Setup

### Create PostgreSQL Database

```sql
CREATE DATABASE nebula_cloud_db;
```

Or via command line:

```bash
createdb nebula_cloud_db -U postgres
```

## Step 5: Configure Environment Variables

Create a `.env` file in the project root:

```ini
# Django
DEBUG=True
DJANGO_SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=localhost,127.0.0.1
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000

# Database
DB_NAME=nebula_cloud_db
DB_USER=postgres
DB_PASSWORD=your-password
DB_HOST=localhost
DB_PORT=5432

# JWT
JWT_ACCESS_TOKEN_LIFETIME_MINUTES=60
JWT_REFRESH_TOKEN_LIFETIME_DAYS=7
JWT_ROTATE_REFRESH_TOKENS=True
JWT_BLACKLIST_AFTER_ROTATION=True
JWT_AUTH_HEADER_TYPE=Bearer

# Storage
STORAGE_BASE_PATH=storage
```

## Step 6: Apply Migrations

```bash
python manage.py migrate
```

## Step 7: Create Superuser

```bash
python manage.py createsuperuser
```

## Step 8: Run the Server

```bash
python manage.py runserver
```

The server will be available at: `http://localhost:8000`

## Step 9: Run Tests (Optional)

```bash
pytest
```

---

## Additional Settings

### CORS

For production mode, specify allowed origins:

```ini
DEBUG=False
CORS_ALLOWED_ORIGINS=["http://localhost:3000","https://yourdomain.com"]
```

### Logging

Logs are saved in the `logs/` directory:

```bash
ls logs/
```

### Static and Media Files

```bash
python manage.py collectstatic
```
