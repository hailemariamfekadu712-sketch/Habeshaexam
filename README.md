# Mekuria Prep

Exam preparation platform for Ethiopian students: account registration, mock exams with a timer and automatic marking, a question bank, study materials, and a progress dashboard.

- **Backend:** Node.js, no npm dependencies (built-in `http`, `crypto`). Passwords are hashed with scrypt, logins use signed tokens, data is stored in `data/db.json`.
- **Frontend:** plain HTML, CSS and JavaScript in `public/`, served by the same Node server.

## Run it

You need Node.js 20.12 or newer.

```bash
cp .env.example .env      # then set JWT_SECRET to a long random string
npm start                 # http://localhost:3000
npm test                  # runs the API tests
```

## Run it on GitHub (Codespaces)

1. Push this folder to a new GitHub repository.
2. Click **Code > Codespaces > Create codespace on main**.
3. The app starts by itself. Open the forwarded port 3000 when VS Code offers it.

The **CI** workflow runs the tests on every push.

## Publish it for real students

GitHub Pages only hosts static files, so split it in two:

1. **Backend:** deploy this repo to a Node host such as Render or Railway. Start command `npm start`. Set the variables `JWT_SECRET`, `CORS_ORIGIN` (your Pages address, e.g. `https://your-name.github.io`) and `DATA_FILE` pointing to a persistent disk.
2. **Frontend:** in the repo, add a variable `API_URL` with your backend address, then run **Actions > Deploy frontend to GitHub Pages**.

## API

| Method | Path | What it does |
| --- | --- | --- |
| POST | `/api/register` | Create an account (`name`, `email`, `password`) and get a token |
| POST | `/api/login` | Log in (`email`, `password`) and get a token |
| GET | `/api/me` | Current user (needs `Authorization: Bearer <token>`) |
| GET | `/api/results` | Your exam results |
| POST | `/api/results` | Save a result (`subject`, `score`, `total`) |
| GET | `/api/health` | Check that the server is up |

## Folder

```
server.js            backend and API
public/              frontend (index.html, config.js)
test/api.test.js     API tests
data/                db.json is created here (not committed)
.github/workflows/   CI and GitHub Pages deploy
.devcontainer/       Codespaces setup
```

## Before real students use it

- The JSON file database suits a prototype. Move to PostgreSQL or SQLite when you have many users.
- Questions are in `public/index.html` (`SUBJECTS`). Marking happens in the browser, so a student could send a fake score. Move the questions and marking to the server before ranking students against each other.
- There is no password reset or email check yet.
