# Nebula Cloud

[🇷🇺 RU версия](./README_RU.md)

A full‑stack cloud file storage web application.

A web application for storing, managing and sharing files. Users can upload, download, rename, delete files and share them via special public links. The interface is a single‑page application (SPA) built with React + TypeScript, the backend is a REST API on Django, and the data is stored in PostgreSQL.

## Main features

### Authentication and user management

* Registration with validation:
  - Username – Latin letters and digits only, the first character must be a letter, length 4–20 characters.
  - Email – validated against a standard email format.
  - Password – minimum 6 characters, must contain at least one uppercase letter, one digit and one special character.
* Login with username and password, session tracking and token refresh.
* An administrator can:
  - view the list of all users,
  - view details of a specific user,
  - edit user details and password,
  - change the admin flag and the account active status,
  - delete users.
* The user list displays storage information:
  - number of files,
  - total size,
  - a link to manage the user’s files.
* Clicking on a selected user in the list opens a full‑screen modal window with user information and management buttons.
* Export user information in JSON format.

### File storage features

* File upload via a button and a drop zone.
* Viewing uploaded files in the upload panel with upload state indication, and the ability to cancel an upload or retry on error.
* Viewing the file list with details: original name, comment, size, upload date, last download date.
* File operations: download, rename, delete, copy special link. Operations can be accessed from a context menu by clicking the button on each list item or by right‑clicking.
* Search by name, upload date.
* Special public link – an anonymised URL through which a file can be downloaded without authentication; the server serves the file with its original name.
* Regular users manage only their own files; an administrator can manage the storage of any user.
* A modal help window showing keyboard shortcuts available in the file manager.
* A progress bar indicating the used disk space.
* File list pagination with a “Load more” button.

### Interface

* Implemented as an SPA: all dynamic data is loaded via API.
* The navigation menu changes depending on the authentication state (Login, Register, Logout).
* An intuitive interface aimed at users familiar with cloud storage services.
* Responsive for desktop monitor resolutions.
* Theme switching (light, dark and system).
* Spinners and skeleton screens while waiting for server responses.
* Notifications for interface interactions.
* Context menu support for the file manager and the user list in the admin panel.
* Keyboard‑driven interface control.
* Animations during interface interactions.
* A welcoming home page and a 404 page.

## Technology stack
* Backend: Python, Django, Django REST Framework, JWT, PostgreSQL
* Frontend: TypeScript, React, Redux Toolkit, React Router, Vite
* File storage: server file system

## Installation and launch

Backend setup instructions [here](./backend/docs/ru/INSTALLATION.md)

Frontend setup instructions [here](./frontend/README.md)

## API

API documentation [here](./backend/docs/ru/API.md)

---

_The application is developed for educational/personal purposes. It is not a commercial product._
