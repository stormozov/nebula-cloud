# API Documentation

[🇷🇺 RU версия](../ru/API.md)

**Base URL:** `http://localhost:8000/api/`

When the server is running, API documentation is available at: `http://127.0.0.1:8000/api/docs/`

---

## Authentication

### User Registration

**Endpoint:** `POST /api/users/auth/register/`

**Request Body:**
```json
{
    "username": "user123",
    "email": "user@example.com",
    "password": "SecurePass123!",
    "password_confirm": "SecurePass123!",
    "first_name": "Ivan",
    "last_name": "Ivanov"
}
```

**Response (201):**
```json
{
    "id": 1,
    "username": "user123",
    "email": "user@example.com",
    "first_name": "Ivan",
    "last_name": "Ivanov"
}
```

---

### User Login

**Endpoint:** `POST /api/users/auth/login/`

**Request Body:**
```json
{
    "username": "user123",
    "password": "SecurePass123!"
}
```

**Response (200):**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhb...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhb...",
    "user": {
        "id": 1,
        "username": "user123",
        "email": "user@example.com",
        "first_name": "Ivan",
        "last_name": "Ivanov"
    }
}
```

---

### User Logout

**Endpoint:** `POST /api/users/auth/logout/`


**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhb..."
}
```

**Response (200):**
```json
{
    "message": "Successfully logged out"
}
```

---

### Token Refresh

**Endpoint:** `POST /api/users/auth/refresh/`


**Request Body:**
```json
{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhb..."
}
```

**Response (200):**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhb..."
}
```

---

## User Profile

### Get Current User

**Endpoint:** `GET /api/users/me/`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
    "id": 1,
    "username": "user123",
    "email": "user@example.com",
    "first_name": "Ivan",
    "last_name": "Ivanov",
    "date_joined": "2024-01-01T12:00:00Z",
    "last_login": "2024-01-02T12:00:00Z"
}
```

---

### Update Profile

**Endpoint:** `PUT /api/users/me/`

**Request Body:**
```json
{
    "first_name": "Petr",
    "last_name": "Petrov"
}
```

---

### Change Password

**Endpoint:** `POST /api/users/me/password/`

**Request Body:**
```json
{
    "old_password": "OldPass123!",
    "new_password": "NewPass123!",
    "new_password_confirm": "NewPass123!"
}
```

---

### Storage Statistics

**Endpoint:** `GET /api/users/me/storage-summary/`

**Response (200):**
```json
{
    "total_files": 10,
    "total_size": 104857600,
    "total_size_formatted": "100 MB",
    "storage_limit": 50,
    "storage_limit_formatted": "50 GB",
    "usage_percent": 50,
    "storage_path": "storage/123/"
}
```

---

### Session Information

**Endpoint:** `GET /api/users/me/session-info/`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
    "user_agent": "Mozilla/5.0...",
    "ip_address": "127.0.0.1",
    "session_start": "2024-01-01T12:00:00Z",
    "last_activity": "2024-01-01T12:05:00Z"
}
```

### Deactivate Account

**Endpoint:** `POST /api/users/me/deactivate/`

**Request Body:**
```json
{
    "password": "YourPass123!"
}
```

---

## File Storage


### Alternative Upload (upload action)
**Endpoint:** `POST /api/storage/files/upload/`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: multipart/form-data
```

**Request Body:**
```
file: <binary>
comment: "My document"
```

**Response (201):** (same as standard upload)

### Standard Upload File
**Endpoint:** `POST /api/storage/files/`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: multipart/form-data
```

**Request Body:**
```
file: <binary>
comment: "My document"
```

**Response (201):**
```json
{
    "id": 1,
    "original_name": "document.pdf",
    "size": 1048576,
    "uploaded_at": "2024-01-01T12:00:00Z",
    "comment": "My document",
    "public_link": null,
    "last_downloaded": null
}
```

---

### List Files

**Endpoint:** `GET /api/storage/files/`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Query Parameters:**
- `page` — Page number (default: 1)
- `page_size` — Page size (default: 100)

**Response (200):**
```json
{
    "count": 10,
    "next": "http://localhost:8000/api/storage/files/?page=2",
    "previous": null,
    "results": [
        {
            "id": 1,
            "original_name": "document.pdf",
            "size": 1048576,
            "uploaded_at": "2024-01-01T12:00:00Z",
            "comment": "My document",
            "public_link": null
        }
    ]
}
```

---

### Download File

**Endpoint:** `GET /api/storage/files/{id}/download/`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** Binary file

---

### Rename File

**Endpoint:** `PATCH /api/storage/files/{id}/rename/`

**Request Body:**
```json
{
    "original_name": "new_name.pdf"
}
```

---

### Add Comment

**Endpoint:** `PATCH /api/storage/files/{id}/comment/`

**Request Body:**
```json
{
    "comment": "New comment"
}
```

---

### Delete File

**Endpoint:** `DELETE /api/storage/files/{id}/`

**Headers:**
```
Authorization: Bearer <access_token>
```

---

## Public Link

### Generate Public Link (replaces existing)

**Endpoint:** `POST /api/storage/files/{id}/public-link/generate`

**Request Body:**
```json
{
    "force": false
}
```

**Response (200):**
```json
{
    "public_link": "abc123xyz"
}
```

### Delete Public Link

**Endpoint:** `DELETE /api/storage/files/{id}/public-link/`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
    "public_link": null
}
```

### Access File via Public Link

**Endpoint:** `GET /api/storage/public/{public_link}/`

**Response:** JSON with file information

### Download via Public Link
**Endpoint:** `GET /api/storage/public/{public_link}/download/`

**Response:** Binary file

---

## Administration

### List Users (Admin Only)

**Endpoint:** `GET /api/admin/users/`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response (200):**
```json
{
    "count": 10,
    "results": [
        {
            "id": 1,
            "username": "admin",
            "email": "admin@example.com",
            "first_name": "Admin",
            "last_name": "Adminov",
            "is_active": true,
            "is_staff": true,
            "date_joined": "2024-01-01T12:00:00Z"
        }
    ]
}
```

---

### Get User Details

**Endpoint:** `GET /api/admin/users/{id}/`

---

### Update User

**Endpoint:** `PUT /api/admin/users/{id}/`

---

### Delete User

**Endpoint:** `DELETE /api/admin/users/{id}/`

---

### Reset Password

**Endpoint:** `POST /api/admin/users/{id}/password/`

**Request Body:**
```json
{
    "new_password": "NewPass123!"
}
```

---

### Toggle Admin Status

**Endpoint:** `POST /api/admin/users/{id}/toggle-admin/`

---

### User Storage Statistics

**Endpoint:** `GET /api/admin/users/{id}/storage-stats/`

---

### Export user data to JSON

**Endpoint:** `GET /api/admin/users/{id}/export/`

**Request Body:**
```json
{
    "id": "123",
    "username": "Adam",
    "email": "adam@mail.ru",
    "full_name": "Adam Rocky",
    "is_staff": false,
    "is_active": true,
    "date_joined": "2024-01-01T12:00:00Z",
    "last_login": "2024-01-01T12:00:00Z",
    "storage_path": "storage/123/",
    "storage_stats": {
        "fileCount": 6,
        "totalSize": 867089,
        "totalSizeFormatted": "846.77 KB"
    }
}
```

---

## Error Codes

| Code | Description           |
| ---- | --------------------- |
| 200  | Success               |
| 201  | Created               |
| 400  | Bad Request           |
| 401  | Unauthorized          |
| 403  | Forbidden             |
| 404  | Not Found             |
| 429  | Too Many Requests     |
| 500  | Internal Server Error |

---

> **Note:** All timestamps are returned in ISO 8601 format (UTC). All string fields in request bodies should be UTF-8 encoded. Authentication is required for all endpoints unless otherwise specified.
