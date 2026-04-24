# Nebula Cloud Frontend

[🇬🇧 EN version](../../README.md)

Клиентская часть веб-приложения Nebula Cloud.

## Технологический стек

- Typescript
- React
- Redux Toolkit
- SCSS
- Axios
- Vite
- Пакетный менеджер [Yarn](https://yarnpkg.com/)
- [react-icons](https://react-icons.github.io/react-icons/)
- [react-toastify](https://www.npmjs.com/package/react-toastify)

Полный список можно посмотреть в [package.json](../../package.json).

Архитектурная методология — Feature-Sliced Design.

## Точка входа

Приложение стартует в [src/main.tsx](../../src/main.tsx).

## Установка

### Установка зависимостей

1. В папке `frontend` выполните команду:

```bash
yarn install
```

Yarn прочитает [package.json](../../package.json) и установит все зависимости в папку `node_modules`.

2. Дождитесь завершения процесса. Вы увидите сообщение об успешном завершении или список ошибок, если они возникли.

### Окружение

Для работы приложения необходимы переменные окружения, описанные в `.env` файле.

В файле `.env` должны быть следующие переменные:

```bash
VITE_API_URL=http://localhost:8000
```

## Основные команды

1. Запустить приложение в режиме разработки:

```bash
yarn dev
```

2. Сборка приложения:

```bash
yarn build
```
