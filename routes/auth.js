const express = require('express');
const router = express.Router();

router.get('/login', (req, res) => {
    res.render('login');
});

router.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === 'admin') {
        res.redirect('/');
    } else {
        res.render('login', { error: 'Invalid username or password' });
    }
});

module.exports = router;
