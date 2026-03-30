# API Документация

[🇬🇧 EN version](../en/API.md)

**Базовый URL:** `http://localhost:8000/api/`

При запуске сервера API документация доступна по адресу: `http://127.0.0.1:8000/api/docs/`

## Аутентификация

### Регистрация пользователя

**Endpoint:** `POST /api/users/auth/register/`

**Request Body:**
```json
{
    "username": "user123",
    "email": "user@example.com",
    "password": "SecurePass123!",
    "password_confirm": "SecurePass123!",
    "first_name": "Иван",
    "last_name": "Иванов"
}
```

**Response (201):**
```json
{
    "id": 1,
    "username": "user123",
    "email": "user@example.com",
    "first_name": "Иван",
    "last_name": "Иванов"
}
```

---

### Вход в систему

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
        "first_name": "Иван",
        "last_name": "Иванов"
    }
}
```

---

### Выход из системы

**Endpoint:** `POST /api/auth/logout/`

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
    "message": "Успешный выход из системы"
}
```

---

### Обновление токена

**Endpoint:** `POST /api/auth/refresh/`

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

## Профиль пользователя

### Получение текущего пользователя

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
    "first_name": "Иван",
    "last_name": "Иванов",
    "date_joined": "2024-01-01T12:00:00Z",
    "last_login": "2024-01-02T12:00:00Z"
}
```

---

### Обновление профиля

**Endpoint:** `PUT /api/users/me/`

**Request Body:**
```json
{
    "first_name": "Пётр",
    "last_name": "Петров"
}
```

---

### Смена пароля

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

### Статистика хранилища

**Endpoint:** `GET /api/users/me/storage-summary/`

**Response (200):**
```json
{
    "total_files": 10,
    "total_size": 104857600,
    "total_size_formatted": "100 MB"
}
```

---

### Деактивация аккаунта

**Endpoint:** `POST /api/users/me/deactivate/`

**Request Body:**
```json
{
    "password": "YourPass123!"
}
```

---

## Файловое хранилище

### Загрузка файла

**Endpoint:** `POST /api/storage/files/`

**Headers:**
```
Authorization: Bearer <access_token>
Content-Type: multipart/form-data
```

**Request Body:**
```
file: <binary>
comment: "Мой документ"
```

**Response (201):**
```json
{
    "id": 1,
    "original_name": "document.pdf",
    "size": 1048576,
    "uploaded_at": "2024-01-01T12:00:00Z",
    "comment": "Мой документ",
    "public_link": null,
    "last_downloaded": null
}
```

---

### Список файлов

**Endpoint:** `GET /api/storage/files/`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Query Parameters:**
- `page` - Номер страницы (по умолчанию: 1)
- `page_size` - Размер страницы (по умолчанию: 100)

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
            "comment": "Мой документ",
            "public_link": null
        }
    ]
}
```

---

### Скачивание файла

**Endpoint:** `GET /api/storage/files/{id}/download/`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:** Бинарный файл

---

### Переименование файла

**Endpoint:** `PATCH /api/storage/files/{id}/rename/`

**Request Body:**
```json
{
    "original_name": "new_name.pdf"
}
```

---

### Добавление комментария

**Endpoint:** `PATCH /api/storage/files/{id}/comment/`

**Request Body:**
```json
{
    "comment": "Новый комментарий"
}
```

---

### Удаление файла

**Endpoint:** `DELETE /api/storage/files/{id}/`

**Headers:**
```
Authorization: Bearer <access_token>
```

---

### Публичная ссылка

#### Создание публичной ссылки

**Endpoint:** `POST /api/storage/files/{id}/generate-public-link/`

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

#### Доступ к файлу по публичной ссылке

**Endpoint:** `GET /api/storage/public/{public_link}/`

**Response:** JSON с информацией о файле

#### Скачивание по публичной ссылке

**Endpoint:** `GET /api/storage/public/{public_link}/download/`

**Response:** Бинарный файл

---

## Администрирование

### Список пользователей (только админ)

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
            "first_name": "Админ",
            "last_name": "Админов",
            "is_active": true,
            "is_staff": true,
            "date_joined": "2024-01-01T12:00:00Z"
        }
    ]
}
```

---

### Детали пользователя

**Endpoint:** `GET /api/admin/users/{id}/`

---

### Обновление пользователя

**Endpoint:** `PUT /api/admin/users/{id}/`

---

### Удаление пользователя

**Endpoint:** `DELETE /api/admin/users/{id}/`

---

### Сброс пароля

**Endpoint:** `POST /api/admin/users/{id}/password/`

**Request Body:**
```json
{
    "new_password": "NewPass123!"
}
```

---

### Переключение статуса админа

**Endpoint:** `POST /api/admin/users/{id}/toggle-admin/`

---

### Статистика хранилища пользователя

**Endpoint:** `GET /api/admin/users/{id}/storage-stats/`

---

### Экспорт данных пользователя в формате JSON

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

## Коды ошибок

| Код | Описание |
|-----|----------|
| 200 | Успешно |
| 201 | Создано |
| 400 | Неверный запрос |
| 401 | Не авторизован |
| 403 | Запрещено |
| 404 | Не найдено |
| 429 | Слишком много запросов |
| 500 | Внутренняя ошибка сервера |
