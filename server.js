const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const uuid = require('uuid');
const session = require('express-session');

const app = express();
const port = 6028;

app.use(bodyParser.urlencoded({ extended: true }));

const db = new sqlite3.Database('library.db');

db.serialize(() => {
  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, firstName TEXT, lastName TEXT)");
  db.run("CREATE TABLE IF NOT EXISTS password_resets (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, token TEXT, timestamp INTEGER)");
});

app.use(express.static('public'));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'your-email@gmail.com',
    pass: 'your-email-password'
  }
});

// Setup session middleware
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

app.post('/signup', async (req, res) => {
  const { username, password, firstName, lastName } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run('INSERT INTO users (username, password, firstName, lastName) VALUES (?, ?, ?, ?)', [username, hashedPassword, firstName, lastName], function(err) {
    if (err) {
      console.error(err);
      return res.status(500).send('User registration failed');
    }
    console.log('User registered successfully:', { username });
    // Set success message in session and redirect to login page
    req.session.successMessage = 'Registration successful. Please log in with your credentials.';
    res.redirect('/login');
  });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) {
      return res.status(400).send('User not found');
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).send('Invalid password');
    }

    // Reset session success message
    req.session.successMessage = null;

    res.send('Login successful');
  });
});


app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const token = uuid.v4();
  const timestamp = Date.now();

  db.run('DELETE FROM password_resets WHERE email = ?', [email], function(err) {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to initiate password reset');
    }

    db.run('INSERT INTO password_resets (email, token, timestamp) VALUES (?, ?, ?)', [email, token, timestamp], function(err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Failed to initiate password reset');
      }

      const resetLink = `http://localhost:${port}/reset-password?token=${token}`;
      res.redirect(`/reset-password?token=${token}`);
    });
  });
});

app.get('/reset-password', (req, res) => {
  res.sendFile(__dirname + '/public/reset-password.html');
});

app.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;

  db.get('SELECT * FROM password_resets WHERE token = ?', [token], async (err, resetInfo) => {
    if (err || !resetInfo) {
      return res.status(400).send('Invalid or expired reset token');
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.run('UPDATE users SET password = ? WHERE username = ?', [hashedPassword, resetInfo.email], function(err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Failed to reset password');
      }

      res.send('Password reset successfully');
    });
  });
});

app.get('/login', (req, res) => {
  // Get success message from session
  const successMessage = req.session.successMessage;
  // Reset success message in session
  req.session.successMessage = null;
  res.sendFile(__dirname + '/public/login.html');
});


app.get('/', (req, res) => {
  // Get success message from session
  const successMessage = req.session.successMessage;
  // Reset success message in session
  req.session.successMessage = null;
  res.sendFile(__dirname + '/public/index.html');
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
