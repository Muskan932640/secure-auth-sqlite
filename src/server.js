
const express = require("express");
const path = require("path");
const fs = require("fs");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const { DatabaseSync } = require("node:sqlite");

const app = express();
const PORT = process.env.PORT || 8000;
const SECRET = process.env.SESSION_SECRET;

// Check session secret
if (!SECRET || SECRET.length < 32) {
    console.error(
        "Error: SESSION_SECRET must be at least 32 characters in .env"
    );
    process.exit(1);
}

// Folders
// server.js is inside src/
// public/ is also inside src/
// data/ is outside src/
const dataFolder = path.join(__dirname, "..", "data");
const publicFolder = path.join(__dirname, "public");

fs.mkdirSync(dataFolder, { recursive: true });

// SQLite database
const db = new DatabaseSync(
    path.join(dataFolder, "auth.sqlite")
);

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL
    )
`);

app.disable("x-powered-by");

app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({
    extended: false,
    limit: "10kb"
}));

// Session configuration
app.use(session({
    name: "secure_auth_sid",
    secret: SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: 2 * 60 * 60 * 1000
    }
}));

// Rate limit for login and registration
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    message: {
        error: "Too many attempts. Try again after 15 minutes."
    }
});

// Serve website files from src/public
app.use(express.static(publicFolder));

// Validate email
function validEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// REGISTER
app.post("/api/register", authLimiter, async (req, res, next) => {
    try {
        const name = String(req.body.name || "").trim();
        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();
        const password = String(req.body.password || "");

        if (name.length < 2 || name.length > 80) {
            return res.status(400).json({
                error: "Name must be 2 to 80 characters."
            });
        }

        if (!validEmail(email)) {
            return res.status(400).json({
                error: "Enter a valid email."
            });
        }

        if (password.length < 10 || password.length > 72) {
            return res.status(400).json({
                error: "Password must be 10 to 72 characters."
            });
        }

        const existing = db.prepare(
            "SELECT id FROM users WHERE email = ?"
        ).get(email);

        if (existing) {
            return res.status(409).json({
                error: "Email is already registered."
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const result = db.prepare(`
            INSERT INTO users (name, email, password_hash)
            VALUES (?, ?, ?)
        `).run(name, email, passwordHash);

        req.session.regenerate((err) => {
            if (err) return next(err);

            req.session.user = {
                id: Number(result.lastInsertRowid),
                name,
                email
            };

            req.session.save((saveErr) => {
                if (saveErr) return next(saveErr);

                res.status(201).json({
                    message: "Registration successful!",
                    user: req.session.user
                });
            });
        });
    } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(409).json({
                error: "Email is already registered."
            });
        }

        next(error);
    }
});

// LOGIN
app.post("/api/login", authLimiter, async (req, res, next) => {
    try {
        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();
        const password = String(req.body.password || "");

        if (!validEmail(email) || !password) {
            return res.status(400).json({
                error: "Enter your email and password."
            });
        }

        const user = db.prepare(
            "SELECT * FROM users WHERE email = ?"
        ).get(email);

        const matched = user
            ? await bcrypt.compare(password, user.password_hash)
            : false;

        if (!matched) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        req.session.regenerate((err) => {
            if (err) return next(err);

            req.session.user = {
                id: user.id,
                name: user.name,
                email: user.email
            };

            req.session.save((saveErr) => {
                if (saveErr) return next(saveErr);

                res.json({
                    message: "Login successful!",
                    user: req.session.user
                });
            });
        });
    } catch (error) {
        next(error);
    }
});

// CHECK CURRENT LOGIN
app.get("/api/me", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({
            error: "Please log in first."
        });
    }

    res.json({
        user: req.session.user
    });
});

// LOGOUT
app.post("/api/logout", (req, res, next) => {
    req.session.destroy((err) => {
        if (err) return next(err);

        res.clearCookie("secure_auth_sid", {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production"
        });

        res.json({
            message: "Logout successful!"
        });
    });
});

// ERROR HANDLER
app.use((err, req, res, next) => {
    console.error(err);

    if (res.headersSent) {
        return next(err);
    }

    res.status(500).json({
        error: "Something went wrong. Please try again."
    });
});

// START SERVER
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log("Database: local SQLite");
});
