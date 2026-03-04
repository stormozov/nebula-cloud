# Установка и настройка

[🇬🇧 EN version](../en/INSTALLATION.md)

## Требования

- Python 3.12.3
- PostgreSQL 18
- Git
- uv 0.10.1

## Шаг 1: Клонирование репозитория

```bash
git clone https://github.com/stormozov/nebula-cloud
cd backend
```

## Шаг 2: Создание и активанция виртуального окружения

### Создание

```bash
uv venv
```

### Активация

```bash
# Windows (PowerShell)
.venv\Scripts\activate

# Windows (Bash)
source .venv/Scripts/activate

# Linux/Mac
source .venv/bin/activate
```

Убедитесь, что виртуальное окружение активировано (в командной строке есть префикс).

## Шаг 3: Установка зависимостей

```bash
uv pip install -e ".[dev]"
```

## Шаг 4: Настройка базы данных

### Создание базы данных PostgreSQL

```sql
CREATE DATABASE nebula_cloud_db;
```

Или через командную строку:

```bash
createdb nebula_cloud_db -U postgres
```

## Шаг 5: Настройка переменных окружения

Создайте файл `.env` в корне проекта:

```env
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

## Шаг 6: Применение миграций

```bash
python manage.py migrate
```

## Шаг 7: Создание суперпользователя

```bash
python manage.py createsuperuser
```

## Шаг 8: Запуск сервера

```bash
python manage.py runserver
```

Сервер будет доступен по адресу: http://localhost:8000

## Шаг 9: Запуск тестов (опционально)

```bash
pytest
```

## Дополнительные настройки

### CORS

Для продакшн режима укажите разрешённые источники:

```env
DEBUG=False
CORS_ALLOWED_ORIGINS=["http://localhost:3000","https://yourdomain.com"]
```

### Логирование

Логи сохраняются в директорию `logs/`:

```bash
ls logs/
```

### Статические и медиа файлы

```bash
python manage.py collectstatic
```
