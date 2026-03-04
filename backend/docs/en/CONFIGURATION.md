# Configuration

[🇷🇺 RU версия](../ru/CONFIGURATION.md)

## Environment Variables

### Main Django Settings

| Variable            | Type | Default               | Description       |
| :------------------ | :--- | :-------------------- | :---------------- |
| `DEBUG`             | bool | `False`               | Debug mode        |
| `DJANGO_SECRET_KEY` | str  | `-`                   | Django secret key |
| `ALLOWED_HOSTS`     | list | `localhost,127.0.0.1` | Allowed hosts     |

### Database

| Variable      | Type | Default             | Description       |
| :------------ | :--- | :------------------ | :---------------- |
| `DB_NAME`     | str  | `cloud_storage_dev` | Database name     |
| `DB_USER`     | str  | `postgres`          | Database user     |
| `DB_PASSWORD` | str  | `-`                 | Database password |
| `DB_HOST`     | str  | `localhost`         | Database host     |
| `DB_PORT`     | str  | `5432`              | Database port     |

### JWT Tokens

| Variable                            | Type | Default  | Description                 |
| :---------------------------------- | :--- | :------- | :-------------------------- |
| `JWT_ACCESS_TOKEN_LIFETIME_MINUTES` | int  | `60`     | Access token lifetime       |
| `JWT_REFRESH_TOKEN_LIFETIME_DAYS`   | int  | `7`      | Refresh token lifetime      |
| `JWT_ROTATE_REFRESH_TOKENS`         | bool | `True`   | Refresh token rotation      |
| `JWT_BLACKLIST_AFTER_ROTATION`      | bool | `True`   | Blacklist old refresh token |
| `JWT_AUTH_HEADER_TYPE`              | str  | `Bearer` | Authorization header type   |

### File Storage

| Variable            | Type | Default     | Description              |
| :------------------ | :--- | :---------- | :----------------------- |
| `STORAGE_BASE_PATH` | str  | `storage`   | Base directory for files |
| `MAX_UPLOAD_SIZE`   | int  | `104857600` | Max file size (100MB)    |

### Example `.env` File

```ini
# Django
DEBUG=True
DJANGO_SECRET_KEY=super-secret-key-change-in-production
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DB_NAME=nebula_cloud_dev
DB_USER=postgres
DB_PASSWORD=mysecretpassword
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

## Django Settings

### Security (Production)

When `DEBUG=False`, the following are applied automatically:

- `SECURE_SSL_REDIRECT = True`
- `SESSION_COOKIE_SECURE = True`
- `CSRF_COOKIE_SECURE = True`
- `SECURE_BROWSER_XSS_FILTER = True`
- `SECURE_CONTENT_TYPE_NOSNIFF = True`
- `X_FRAME_OPTIONS = "DENY"`
- `SECURE_HSTS_SECONDS = 31536000`
- `SECURE_HSTS_INCLUDE_SUBDOMAINS = True`
- `SECURE_HSTS_PRELOAD = True`

### CORS

**Development:**

- `CORS_ALLOW_ALL_ORIGINS = True`
- `CORS_ALLOW_CREDENTIALS = True`

**Production:**

- `CORS_ALLOWED_ORIGINS = ["http://localhost:3000", "https://yourdomain.com"]`

### Rate Limiting

| Class            | Limit     | Description         |
| :--------------- | :-------- | :------------------ |
| `anon`           | 100/hour  | Anonymous users     |
| `user`           | 1000/hour | Authenticated users |
| `login`          | 10/hour   | Login attempts      |
| `register`       | 5/hour    | Registration        |
| `reset_password` | 5/hour    | Password reset      |

### Password Validation

**Password Requirements:**
- Minimum 6 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character
- Should not resemble the username

### Uploaded Files

**Allowed Extensions:**
- `pdf`, `doc`, `docx`, `xls`, `xlsx`, `ppt`, `pptx`
- `jpg`, `jpeg`, `png`, `gif`, `bmp`, `svg`, `txt`, `rtf`, `csv`
- `mp3`, `wav`, `mp4`, `avi`, `mov`, `mkv`
- `zip`, `rar`, `7z`, `tar`, `gz`

**Maximum Size:** 100 MB

### Language and Timezone

- `LANGUAGE_CODE = "ru-ru"`
- `TIME_ZONE = "Europe/Moscow"`

## Logging Configuration

**Logs are saved in:**

- `logs/django.log` - Main Django logs
- `logs/access.log` - API access logs
- `logs/error.log` - Error logs

**Logging Levels:**

- `DEBUG` - Detailed information
- `INFO` - General information
- `WARNING` - Warnings
- `ERROR` - Errors
- `CRITICAL` - Critical errors

## Testing Configuration

**When running tests, the following are applied automatically:**

- **MD5PasswordHasher** - Fast password hashing
- **Temporary directory** for media files
- **Disabled** request rate limiting (throttling)

## Swagger/OpenAPI

**Settings in `SPECTACULAR_SETTINGS`:**

- **TITLE:** Nebula Cloud API
- **VERSION:** 1.0.0
- **TAGS:** Auth, Users, Files
