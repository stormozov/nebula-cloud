# Nebula Cloud Backend

[🇷🇺 RU версия](docs/ru/README.md)

Backend application for cloud data storage built on Django.

## Technology Stack

- Django 6.0
- Django REST Framework 3.15
- PostgreSQL
- JWT (djangorestframework-simplejwt)
- Swagger/OpenAPI (drf-spectacular)

## Project Structure

```
backend/
├── core/              # Main project settings
│   ├── settings.py    # Django settings
│   ├── urls.py        # Root URLs
│   ├── wsgi.py        # WSGI configuration
│   ├── asgi.py        # ASGI configuration
│   ├── utils.py       # Utilities
│   └── logging_config.py  # Logging settings
├── users/             # Users application
│   └── services/      # Business logic
│   ├── serializers/   # Serializers
│   ├── views/         # Views
│   ├── models.py      # UserAccount model
│   ├── urls.py        # URL routes
│   ├── permissions.py # Access permissions
│   ├── validators.py  # Validators
│   ├── throttles.py   # Rate limiting
│   ├── signals.py     # Signals
│   ├── managers.py    # Managers
├── storage/           # File storage application
│   ├── serializers/   # Serializers
│   ├── views/         # Views
│   ├── models.py      # File model
│   ├── urls.py        # URL routes
│   ├── permissions.py # Access permissions
│   └── utils.py       # Utilities
└── docs/              # Documentation
```

## Quick Start

See [INSTALLATION.md](docs/en/INSTALLATION.md) for installation instructions.

## Configuration

See [CONFIGURATION.md](docs/en/CONFIGURATION.md)

## API Documentation

After starting the server, documentation (generated with Swagger/OpenAPI) is available at:

- **Swagger UI:** `http://localhost:8000/api/docs/`
- **OpenAPI Schema:** `http://localhost:8000/api/schema/`

Also, documentation is available [here](docs/en/API.md)

## Testing

See [TESTING.md](docs/en/TESTING.md) for instructions on running tests.

## Main Features

### Authentication

- New user registration
- Login with username/password
- Logout with token blacklisting
- Access token refresh

### User Management

- View and edit profile
- Change password
- Account deactivation
- View storage statistics

### File Storage

- Upload files
- Download files
- Rename files
- Add comments
- Public file links
- View download history

## License

MIT
