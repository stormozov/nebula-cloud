# Архитектура проекта

[🇬🇧 EN version](../en/ARCHITECTURE.md)

## Обзор

Nebula Cloud — это облачное хранилище файлов с REST API на Django.

## Архитектурные принципы

1. **MVC Pattern** - Django следует паттерну MVT (Model-View-Template)
2. **Single Responsibility** - Приложения разделены по функциональности
3. **DRY** - Использование наследования и миксинов
4. **KISS** - Простой и понятный код

## Структура приложений

### Users (Пользователи)

Отвечает за:
- Управление пользователями
- Аутентификация и авторизация
- JWT токены
- Права доступа

**Ключевые компоненты:**

```
users/
├── views/             # API Views
│   ├── auth_views.py  # Регистрация, вход, выход
│   ├── users_views.py # Профиль пользователя
│   └── admin_views.py # Админ-функции
├── serializers/       # Сериализация данных
├── services/          # Бизнес-логика
├── models.py          # UserAccount (кастомная модель пользователя)
├── permissions.py     # Права доступа
├── validators.py      # Валидация полей
├── throttles.py       # Ограничение частоты запросов
├── signals.py         # Сигналы Django
└── managers.py        # Кастомный менеджер пользователей
```

### Storage (Хранилище)

Отвечает за:
- Загрузка файлов
- Управление файлами
- Публичные ссылки
- Изоляция файлов пользователей

**Ключевые компоненты:**

```
storage/
├── views/                     # API Views
│   ├── crud_views.py          # CRUD операции с файлами
│   └── public_views.py        # Публичный доступ
├── serializers/               # Сериализация
│   ├── crud_serializers.py    # Для владельца
│   └── public_serializers.py  # Для публичного доступа
├── models.py                  # File модель
├── permissions.py             # Права доступа
└── utils.py                   # Утилиты
```

## Поток данных

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

## База данных

### PostgreSQL

Используется PostgreSQL 18 для:
- Надёжности
- Производительности
- ACID соответствия

### Модели

#### UserAccount

| Поле | Тип | Описание |
|------|-----|----------|
| id | BigAutoField | ID |
| username | CharField | Уникальный логин |
| email | EmailField | Уникальный email |
| first_name | CharField | Имя |
| last_name | CharField | Фамилия |
| password | CharField | Хэш пароля |
| is_active | BooleanField | Активен |
| is_staff | BooleanField | Staff |
| is_superuser | BooleanField | Суперпользователь |
| date_joined | DateTimeField | Дата регистрации |
| last_login | DateTimeField | Последний вход |

#### File

| Поле | Тип | Описание |
|------|-----|----------|
| id | BigAutoField | ID |
| owner | ForeignKey | Владелец (UserAccount) |
| file | FileField | Физический файл |
| original_name | CharField | Оригинальное имя |
| size | BigIntegerField | Размер в байтах |
| uploaded_at | DateTimeField | Дата загрузки |
| last_downloaded | DateTimeField | Последнее скачивание |
| comment | TextField | Комментарий |
| public_link | CharField | Публичная ссылка |

## Безопасность

### Аутентификация

- JWT токены (access + refresh)
- Blacklist для refresh токенов
- HttpOnly cookies опционально

### Авторизация

- Права владельца файла
- Admin permissions
- Permission classes в DRF

### Защита

- Валидация паролей (сложность)
- Rate limiting (throttling)
- CORS настройки
- CSRF защита

## Кэширование

В текущей реализации:
- Нет внешнего кэширования
- Django ORM кэширование по умолчанию
- Возможность добавления Redis в будущем

## Логирование

Настройки в `core/logging_config.py`:
- Файловые хендлеры
- Консольный вывод
- Разные уровни для разных компонентов
- Логи в директории `logs/`

## Тестирование

- pytest + pytest-django
- Factory Boy для тестовых данных
- Изоляция базы данных
- Покрытие 80%+

## Масштабирование

### Горизонтальное

- Load balancer
- Multiple Django instances
- Shared storage (NFS/S3)

### Вертикальное

- Оптимизация запросов
- Database indexing
- Connection pooling

## Технологический стек

| Компонент | Технология |
|-----------|------------|
| Backend | Django 6.0 |
| API | DRF 3.15 |
| Database | PostgreSQL |
| Auth | JWT |
| Docs | drf-spectacular |
| Testing | pytest |
| Linting | ruff, black |
