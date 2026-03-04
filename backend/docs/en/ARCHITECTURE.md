# Project Architecture

[🇷🇺 RU версия](../ru/ARCHITECTURE.md)

## Overview

Nebula Cloud is a cloud file storage with REST API built on Django.

## Architectural Principles

- **MVC Pattern** - Django follows the MVT (Model-View-Template) pattern
- **Single Responsibility** - Application is divided by functionality
- **DRY** - Using inheritance and mixins
- **KISS** - Simple and understandable code

## Application Structure

### Users

**Responsible for:**

- User management
- Authentication and authorization
- JWT tokens
- Access rights

**Key Components:**

```
users/
├── views/             # API Views
│   ├── auth_views.py  # Registration, login, logout
│   ├── users_views.py # User profile
│   └── admin_views.py # Admin functions
├── serializers/       # Data serialization
├── services/          # Business logic
├── models.py          # UserAccount (custom user model)
├── permissions.py     # Access permissions
├── validators.py      # Field validation
├── throttles.py       # Rate limiting
├── signals.py         # Django signals
└── managers.py        # Custom user manager
```

### Storage

**Responsible for:**

- File upload
- File management
- Public links
- User file isolation

**Key Components:**

```
storage/
├── views/                     # API Views
│   ├── crud_views.py          # CRUD operations with files
│   └── public_views.py        # Public access
├── serializers/               # Serialization
│   ├── crud_serializers.py    # For owner
│   └── public_serializers.py  # For public access
├── models.py                  # File model
├── permissions.py             # Access permissions
└── utils.py                   # Utilities
```

## Data Flow

```
Client Request
    ↓
URL Router (urls.py)
    ↓
View (views.py)
    ↓
Authentication (JWT)
    ↓
Permissions
    ↓
Business Logic (Services)
    ↓
Serializer (Validation)
    ↓
Model (Database)
    ↓
Response
```

## Database

**PostgreSQL**

PostgreSQL 18 is used for:
- Reliability
- Performance
- ACID compliance

## Models

### UserAccount

| Field          | Type          | Description       |
| :------------- | :------------ | :---------------- |
| `id`           | BigAutoField  | ID                |
| `username`     | CharField     | Unique login      |
| `email`        | EmailField    | Unique email      |
| `first_name`   | CharField     | First name        |
| `last_name`    | CharField     | Last name         |
| `password`     | CharField     | Password hash     |
| `is_active`    | BooleanField  | Active            |
| `is_staff`     | BooleanField  | Staff             |
| `is_superuser` | BooleanField  | Superuser         |
| `date_joined`  | DateTimeField | Registration date |
| `last_login`   | DateTimeField | Last login        |

### File

| Field             | Type            | Description         |
| :---------------- | :-------------- | :------------------ |
| `id`              | BigAutoField    | ID                  |
| `owner`           | ForeignKey      | Owner (UserAccount) |
| `file`            | FileField       | Physical file       |
| `original_name`   | CharField       | Original name       |
| `size`            | BigIntegerField | Size in bytes       |
| `uploaded_at`     | DateTimeField   | Upload date         |
| `last_downloaded` | DateTimeField   | Last download       |
| `comment`         | TextField       | Comment             |
| `public_link`     | CharField       | Public link         |

## Security

### Authentication

- JWT tokens (access + refresh)
- Blacklist for refresh tokens
- HttpOnly cookies (optional)

### Authorization

- File owner permissions
- Admin permissions
- Permission classes in DRF

### Protection

- Password validation (complexity)
- Rate limiting (throttling)
- CORS settings
- CSRF protection

## Caching

**In the current implementation:**

- No external caching
- Django ORM caching by default
- Ability to add Redis in the future

## Logging

**Settings in `core/logging_config.py`:**

- File handlers
- Console output
- Different levels for different components
- Logs in `logs/` directory

## Testing

- pytest + pytest-django
- Factory Boy for test data
- Database isolation
- Coverage 80%+

## Scaling

### Horizontal

- Load balancer
- Multiple Django instances
- Shared storage (NFS/S3)

### Vertical

- Query optimization
- Database indexing
- Connection pooling

## Technology Stack

| Component | Technology      |
| :-------- | :-------------- |
| Backend   | Django 6.0      |
| API       | DRF 3.15        |
| Database  | PostgreSQL      |
| Auth      | JWT             |
| Docs      | drf-spectacular |
| Testing   | pytest          |
| Linting   | ruff, black     |
