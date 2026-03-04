# Конфигурация

[🇬🇧 EN version](../en/CONFIGURATION.md)

## Переменные окружения

### Основные настройки Django

| Переменная | Тип | По умолчанию | Описание |
|------------|-----|--------------|----------|
| `DEBUG` | bool | False | Режим отладки |
| `DJANGO_SECRET_KEY` | str | - | Секретный ключ Django |
| `ALLOWED_HOSTS` | list | localhost,127.0.0.1 | Разрешённые хосты |

### База данных

| Переменная | Тип | По умолчанию | Описание |
|------------|-----|--------------|----------|
| `DB_NAME` | str | cloud_storage_dev | Имя базы данных |
| `DB_USER` | str | postgres | Пользователь БД |
| `DB_PASSWORD` | str | - | Пароль БД |
| `DB_HOST` | str | localhost | Хост БД |
| `DB_PORT` | str | 5432 | Порт БД |

### JWT токены

| Переменная | Тип | По умолчанию | Описание |
|------------|-----|--------------|----------|
| `JWT_ACCESS_TOKEN_LIFETIME_MINUTES` | int | 60 | Время жизни access токена |
| `JWT_REFRESH_TOKEN_LIFETIME_DAYS` | int | 7 | Время жизни refresh токена |
| `JWT_ROTATE_REFRESH_TOKENS` | bool | True | Ротация refresh токенов |
| `JWT_BLACKLIST_AFTER_ROTATION` | bool | True | Блокировка старого refresh |
| `JWT_AUTH_HEADER_TYPE` | str | Bearer | Тип заголовка авторизации |

### Файловое хранилище

| Переменная | Тип | По умолчанию | Описание |
|------------|-----|--------------|----------|
| `STORAGE_BASE_PATH` | str | storage | Базовая директория для файлов |
| `MAX_UPLOAD_SIZE` | int | 104857600 | Макс. размер файла (100MB) |

### Пример .env файла

```env
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

## Настройки Django

### Безопасность (Production)

При `DEBUG=False` автоматически применяются:

```python
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
```

### CORS

**Development:**
```python
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True
```

**Production:**
```python
CORS_ALLOWED_ORIGINS = ["http://localhost:3000", "https://yourdomain.com"]
```

### Rate Limiting

| Класс | Лимит | Описание |
|-------|-------|----------|
| anon | 100/hour | Анонимные пользователи |
| user | 1000/hour | Авторизованные пользователи |
| login | 10/hour | Попытки входа |
| register | 5/hour | Регистрация |
| reset_password | 5/hour | Сброс пароля |

### Валидация пароля

Требования к паролю:
- Минимум 6 символов
- Минимум 1 заглавная буква
- Минимум 1 строчная буква
- Минимум 1 цифра
- Минимум 1 специальный символ
- Не должен быть похож на username

### Загружаемые файлы

Разрешённые расширения:
```
pdf, doc, docx, xls, xlsx, ppt, pptx,
jpg, jpeg, png, gif, bmp, svg, txt, rtf, csv,
mp3, wav, mp4, avi, mov, mkv,
zip, rar, 7z, tar, gz
```

Максимальный размер: 100 MB

### Язык и часовой пояс

```python
LANGUAGE_CODE = "ru-ru"
TIME_ZONE = "Europe/Moscow"
```

## Настройка логирования

Логи сохраняются в:
- `logs/django.log` - Основные логи Django
- `logs/access.log` - Доступ к API
- `logs/error.log` - Ошибки

Уровни логирования:
- DEBUG - Подробная информация
- INFO - Общая информация
- WARNING - Предупреждения
- ERROR - Ошибки
- CRITICAL - Критические ошибки

## Настройка тестирования

При запуске тестов автоматически:
- Используется MD5PasswordHasher
- Создаётся временная директория для файлов
- Отключается throttling

## Swagger/OpenAPI

Настройки в `SPECTACULAR_SETTINGS`:

- **TITLE**: Nebula Cloud API
- **VERSION**: 1.0.0
- **TAGS**: Auth, Users, Files
