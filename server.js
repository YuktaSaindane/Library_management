//Loading environment variables from the .env file
require('dotenv').config(); 

const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const https = require('https');
const fs = require('fs');
const uuid = require('uuid');

const app = express();
const port = 3000; //Defining the port the server will listen on

//Setting up email transporter using the environment variables for email credentials
const transporter = nodemailer.createTransport({
    host: 'smtp-mail.outlook.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,  //Email address from the .env file
        pass: process.env.EMAIL_PASS  //Password from the .env file
    }
});

app.use(bodyParser.urlencoded({ extended: true })); //Parsing the URL encoded bodies
app.use(bodyParser.json()); //Parsing the JSON bodies
app.use(cookieParser());//Parsing the cookies
app.use(express.static('public'));//Serving static files from the public directory

//Creating SQLIte connection
const db = new sqlite3.Database('library.db');

// Create tables if not exists
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password TEXT,
        firstName TEXT,
        lastName TEXT,
        pin TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT,
        token TEXT,
        timestamp INTEGER
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS books (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        author TEXT,
        category TEXT
    )`);

    
});

//Forgot password 
app.post('/forgot-password', async (req, res) => {
    const { username, email, pin } = req.body;

    //Checking if the user exists in the database
    db.get('SELECT * FROM users WHERE username = ? AND email = ?', [username, email], async (err, user) => {
        if (err || !user) {
            return res.status(400).send('User does not exist');
        }

        //Validating the pin
        console.log('User:', user);
        console.log('Provided pin:', pin);

        if (!user.pin) {
            return res.status(400).send('Pin not set for this user');
        }

        const isPinValid = await bcrypt.compare(pin, user.pin);
        if (!isPinValid) {
            return res.status(400).send('Invalid pin');
        }

    //Deleting any existing password reset token for the email address
        db.run('DELETE FROM password_resets WHERE email = ?', [email], function(err) {
            if (err) {
                console.error(err);
                return res.status(500).send('Failed to initiate password reset');
            }

            //Generating unique token for each user for password reset
            const token = uuid.v4();
            const timestamp = Date.now();

            //Storing that token and timestamp in password_resets table
            db.run('INSERT INTO password_resets (email, token, timestamp) VALUES (?, ?, ?)', [email, token, timestamp], function(err) {
                if (err) {
                    console.error(err);
                    return res.status(500).send('Failed to initiate password reset');
                }

                //Sending the email with password reset link to the users email address
                const resetUrl = `https://3.106.227.0:{port}/reset-password.html?token=${token}`;
                const mailOptions = {
                    from: process.env.EMAIL_USER, // Your Outlook email address from .env
                    to: email,
                    subject: 'Password Reset',
                    text: `Please click the following link to reset your password: ${resetUrl}`
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error(error);
                        return res.status(500).send('Failed to send password reset email');
                    }
                    console.log('Password reset email sent:', info.response);
                    res.redirect(`/forgot-password.html?success=Password reset email sent`);
                });
            });
        });
    });
});

//Reset password route
app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    //Checking if the token exists and is not expired
    db.get('SELECT * FROM password_resets WHERE token = ?', [token], async (err, resetInfo) => {
        if (err || !resetInfo) {
            return res.status(400).send('Invalid or expired reset token');
        }

        //Ensuring the user enters secure password
        if (!isPasswordSecure(newPassword)) {
            return res.status(400).send('Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one number, and one special character.');
        }

        //Updating the users new password in database
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.run('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, resetInfo.email], function(err) {
            if (err) {
                console.error(err);
                return res.status(500).send('Failed to reset password');
            }

            //Deleteing the unique token from the database after resetting the password
            db.run('DELETE FROM password_resets WHERE token = ?', [token], function(err) {
                if (err) {
                    console.error(err);
                    return res.status(500).send('Failed to reset password');
                }
                 //Redirecting to the login page with success message upon successfull password reset
                res.redirect(`/login.html?success=Password reset successful. Please log in with your new password.`);
            });
        });
    });
});

//Function for checking the password strength
function isPasswordSecure(password) {
    const regex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9]).{8,}$/;
    return regex.test(password);
}

//Signup route
app.post('/signup', [
    body('email').isEmail(),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email } = req.body;

    db.run(`INSERT INTO users (email, role) VALUES (?, ?)`, [email, 'non user'], function(err) {
        if (err) {
            console.error(err);
            return res.redirect('/signup.html?error=Signup failed');
        }
        console.log('User signed up successfully:', { email });
        const token = jwt.sign({ id: this.lastID, email, role: 'non user' }, secretKey, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/dashboard.html?role=non user');
    });
});

//Register route
app.post('/register', [
    body('username').notEmpty(), //validating username field is not empty
    body('email').isEmail(),//validating the email
    body('password').isLength({ min: 8 }).matches(/[a-z]/).matches(/[A-Z]/).matches(/[0-9]/).matches(/[^a-zA-Z0-9]/),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, firstName, lastName, pin } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedPin = await bcrypt.hash(pin, 10);

    db.run(`INSERT INTO users (username, email, password, firstName, lastName, pin, role) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [username, email, hashedPassword, firstName, lastName, hashedPin, 'user'],
        function(err) {
            if (err) {
                console.error(err);
                return res.redirect('/register.html?error=User registration failed');
            }
           
            res.redirect('/login.html?success=Registration successful. Please log in.');
        }
    );
});

//Dashboard route
app.get('/dashboard', (req, res) => {
    const token = req.cookies.token;

    if (!token) {
       //If the user is not logged in,redirecting him to the login page
        return res.redirect('/login.html?error=Please log in');
    }

    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            //if the token verification is not successfull,redirecting the user to login page
            return res.redirect('/login.html?error=Please log in again');
        }

        //Checking the user role
        if (user.role === 'non user') {
            //Displaying a message for non users
            return res.sendFile(__dirname + '/dashboard.html?role=non user'); //Sending the user role to the dashboard
        }

        //if the user is registered,redirecting him to the dashboard
        res.redirect('/dashboard.html');
    });
});

//Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            return res.redirect('/login.html?error=Invalid username or password or user does not exist');
        }
    //compairing the user entered password with the password stpred in the database
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.redirect('/login.html?error=Invalid username or password');
        }
        
        //Generating a token
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, secretKey, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true });
        res.redirect(`/dashboard.html?role=${user.role}`);
    });
});


//Search books route
app.get('/search-books', (req, res) => {
    const query = req.query.query;
    //Allowing users to search by using any field
    db.all(`SELECT * FROM books WHERE title LIKE ? OR author LIKE ? OR category LIKE ?`, [`%${query}%`, `%${query}%`, `%${query}%`], (err, rows) => {
        if (err) {
            console.error(err);
            return res.status(500).json([]);
        }
        
        //Verifying if the user is logged in
        const token = req.cookies.token;
        if (!token) {
            //If the user is not logged in then we return the books without access and download buttons
            return res.json(rows.map(book => ({
                ...book,
                access: false, //Non users have no access
                download: false //Non users have no download permission
            })));
        }

        jwt.verify(token, secretKey, (err, user) => {
            if (err) {
                //If the token verification fails,returning the books withour access and download benefits
                return res.json(rows.map(book => ({
                    ...book,
                    access: false, // Non-registered users have no access
                    download: false // Non-registered users have no download permission
                })));
            }

           //Checking the role of the user
            if (user.role === 'non user') {
                // If user is not registered, return books without access and download buttons
                return res.json(rows.map(book => ({
                    ...book,
                    access: false, // Non-registered users have no access
                    download: false // Non-registered users have no download benefits
                })));
            }

//If the user is registered,returning books with access and download buttons
            res.json(rows.map(book => ({
                ...book,
                access: true, 
                download: true 
            })));
        });
    });
});



//Access book route
app.get('/access-book/:bookId', (req, res) => {
    const bookId = req.params.bookId;
    //Fetching the file path of the PDF associated with the book ID from the database
    db.get('SELECT pdf_path FROM books WHERE id = ?', [bookId], (err, book) => {
        if (err || !book) {
            return res.status(404).send('Book not found');
        }
        const filePath = `${__dirname}/public/${book.pdf_path}`;
        res.sendFile(filePath);
    });
});

//Download book route
app.get('/download-book/:bookId', (req, res) => {
    const bookId = req.params.bookId;
    //Fetch the file path of the PDF associated with the bookID from the database
    db.get('SELECT pdf_path FROM books WHERE id = ?', [bookId], (err, book) => {
        if (err || !book) {
            return res.status(404).send('Book not found');
        }
        const filePath = `${__dirname}/public/${book.pdf_path}`;
        res.download(filePath);
    });
});



//Fetching the available books
app.get('/available-books', (req, res) => {
    db.all('SELECT * FROM books', (err, books) => {
        if (err) {
            console.error('Error fetching available books:', err);
            return res.status(500).json({ error: 'Internal server error' });
        }
        res.json(books);
    });
});
//Authenticating the JWT token using middleware
function authenticateToken(req, res, next) {
    const token = req.cookies.token;

    if (!token) {
        return res.redirect('/login.html?error=Please log in');
    }

    jwt.verify(token, secretKey, (err, user) => {
        if (err) {
            return res.redirect('/login.html?error=Please log in again');
        }

        req.user = user;
        next();
    });
}

//Loading the SSL certificate and the private key
const privateKey = fs.readFileSync('new_key.pem', 'utf8');
const certificate = fs.readFileSync('cert.pem', 'utf8');
const credentials = { key: privateKey, cert: certificate };

//passphrase used to decrypt private key
const passphrase = process.env.SSL_PASSPHRASE; //Passphrase stored in .env

//Creating https server with correct credentials
const httpsServer = https.createServer({ ...credentials, passphrase }, app);

//Generating the secret key
function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

const secretKey = generateRandomString(32); //generated secret key
console.log("Generated Secret Key:", secretKey);

//Starting the server
httpsServer.listen(port, '0.0.0.0', () => {
    console.log(`Server running on https://3.106.227.0:${port}`);
});
