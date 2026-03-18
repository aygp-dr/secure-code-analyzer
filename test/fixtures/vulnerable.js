/**
 * Intentionally vulnerable JavaScript code for testing SecureCodeAnalyzer.
 */
const fs = require('fs');
const path = require('path');
const db = require('./db');

// SQL Injection — string concatenation
function getUser(name) {
    db.query("SELECT * FROM users WHERE name='" + name + "'");
}

// XSS — innerHTML
function renderUser(data) {
    document.getElementById("user").innerHTML = data;
}

// XSS — document.write
function renderPage(content) {
    document.write(content);
}

// Hardcoded secrets
const api_key = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
const password = "admin_password_123";

// Eval usage
function processCode(code) {
    eval(code);
}

// Eval — new Function
function dynamicFunc(body) {
    return new Function(body);
}

// Insecure random
function generateToken() {
    return Math.random().toString(36).substring(2);
}

// Path traversal — readFile from request
const express = require('express');
const app = express();

app.get('/file', (req, res) => {
    fs.readFile(req.query.path, 'utf8', (err, data) => {
        res.send(data);
    });
});

// Open redirect
app.get('/redirect', (req, res) => {
    res.redirect(req.query.url);
});
