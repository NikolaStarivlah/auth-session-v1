// Require Express.js framework for building web applications
const express = require("express");
// Require express-session middleware for managing user sessions
const session = require("express-session");
// Require body-parser middleware to parse incoming request bodies (deprecated in favor of express built-in, but used here for demo)
const bodyParser = require("body-parser");

// Initialize the Express application
const app = express();

// Set EJS as the template engine for rendering views
app.set("view engine", "ejs");
// Use body-parser middleware to parse URL-encoded data from forms
app.use(bodyParser.urlencoded({ extended: true }));

// VULNERABLE SESSION CONFIG
// This session configuration is intentionally insecure for demonstration purposes.
// - 'secret' is a weak, hardcoded secret key that should be a strong, random string in production.
// - 'saveUninitialized: true' allows creating sessions for unauthenticated users, enabling session fixation attacks.
app.use(session({
    secret: "secretkey", // weak
    resave: false,
    saveUninitialized: true // allows session fixation
}));

// Fake user database
// In a real application, this would be replaced with a secure database.
// Here, we use a simple array to simulate user storage for demonstration.
const users = [
    { username: "admin", password: "admin123", role: "admin" },
    { username: "user", password: "password", role: "user" }
];

// Login page
// GET route to display the login form to the user
app.get("/", (req, res) => {
    res.render("login");
});

// Vulnerable login
// POST route to handle user login. This implementation has several security vulnerabilities.
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);

    // Username enumeration
    // By responding differently for non-existent users, an attacker can enumerate valid usernames.
    if (!user) {
        return res.send("User not found");
    }

    if (user.password !== password) {
        return res.send("Incorrect password");
    }

    // No session regeneration (session fixation)
    // After login, the session ID is not regenerated, allowing session fixation attacks where an attacker can set the session ID beforehand.
    req.session.user = user.username;
    req.session.role = user.role;

    res.redirect("/dashboard");
});

// Dashboard
// GET route for the user dashboard. Checks if the user is authenticated via session.
app.get("/dashboard", (req, res) => {
    if (!req.session.user) {
        return res.redirect("/");
    }

    res.render("dashboard", {
        user: req.session.user,
        role: req.session.role
    });
});

// Weak admin check
// GET route for the admin page. This check is insufficient for secure authorization.
app.get("/admin", (req, res) => {
    // Only checks role, no strong validation
    // This only verifies the session role without additional checks like re-authentication or proper authorization logic.
    if (req.session.role !== "admin") {
        return res.send("Access denied");
    }

    res.render("admin");
});

app.listen(3000, () => {
    console.log("Auth lab running on http://localhost:3000");
});