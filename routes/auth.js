const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../db');
require('dotenv').config();

const router = express.Router();

// Signup (Student/Teacher)
router.post('/signup', async (req, res) => {
    const { name, email, password, role, subject } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    if (role === "teacher") {
        db.query("INSERT INTO subject (name) VALUES (?)", [subject], (err, result) => {
            if (err) return res.status(500).json(err);
            const subject_id = result.insertId;
            db.query("INSERT INTO teacher (name, email, password, subject_id) VALUES (?, ?, ?, ?)",
                [name, email, hashedPassword, subject_id], (err) => {
                    if (err) return res.status(500).json(err);
                    res.json({ message: "Teacher registered!" });
                });
        });
    } else {
        db.query("INSERT INTO student (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword], (err) => {
                if (err) return res.status(500).json(err);
                res.json({ message: "Student registered!" });
            });
    }
});

// Login
router.post('/login', (req, res) => {
    const { email, password, role } = req.body;
    const table = role === "teacher" ? "teacher" : "student";

    db.query(`SELECT * FROM ${table} WHERE email = ?`, [email], async (err, result) => {
        if (err || result.length === 0) return res.status(400).json({ error: "Invalid Email/Password" });

        const user = result[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) return res.status(400).json({ error: "Invalid Email/Password" });

        const token = jwt.sign({ id: user.teacher_id || user.student_id, role }, process.env.JWT_SECRET);
        res.json({ token, role });
    });
});

module.exports = router;
