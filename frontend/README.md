# Nebula Cloud Frontend

[🇷🇺 RU версия](docs/ru/README.md)

Client-side of the Nebula Cloud web application.

## Technology stack

- Typescript
- React
- Redux Toolkit
- SCSS
- Axios
- Vite
- Package manager [Yarn](https://yarnpkg.com/)
- [react-icons](https://react-icons.github.io/react-icons/)
- [react-toastify](https://www.npmjs.com/package/react-toastify)

The full list can be found in [package.json](./package.json).

Architectural methodology — Feature-Sliced Design.

## Entry point

The application starts at [src/main.tsx](./src/main.tsx).

## Installation

### Installing dependencies

1. In the `frontend` folder, run the command:

```bash
yarn install
```

Yarn will read [package.json](./package.json) and install all dependencies into the `node_modules` folder.

2. Wait for the process to complete. You will see a success message or a list of errors if any occurred.

### Environment

The application requires environment variables defined in the `.env` file.

The `.env` file should contain the following variables:

```bash
VITE_API_URL=http://localhost:8000
```

## Main commands

1. Start the application in development mode:

```bash
yarn dev
```

2. Build the application:

```bash
yarn build
```
