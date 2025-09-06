CREATE TABLE IF NOT EXISTS project (
    id          INTEGER PRIMARY KEY,
    "name"      TEXT UNIQUE NOT NULL CHECK (LENGTH("name") > 3)
);

CREATE TABLE IF NOT EXISTS user (
    id                 INTEGER PRIMARY KEY,
    username           TEXT UNIQUE NOT NULL CHECK (LENGTH(username) > 3),
    password_digest    TEXT UNIQUE NOT NULL CHECK (LENGTH(password_digest) = 60)
);

CREATE TABLE IF NOT EXISTS todo (
    id          INTEGER PRIMARY KEY,
    project_id  INTEGER NOT NULL,
    title       TEXT NOT NULL CHECK (LENGTH(title) > 3),
    done        BOOLEAN NOT NULL DEFAULT FALSE,

    FOREIGN KEY (project_id) REFERENCES project (id) ON DELETE CASCADE
);
