const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const config = require('./config.json');
const cors = require('cors');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const flash = require('connect-flash');
const fs = require('fs');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: false 
}));

app.use(flash());

const twitchClientId = 'jvpjgbm0dygvjqirgdnf6nzucsrdkr';

const dbPath = path.resolve(__dirname, 'data', 'database.db');
const db = new sqlite3.Database(dbPath, err => {
    if (err) {
        console.error('Error connecting to SQLite database:', err.message);
    } else {
        console.log('Connected to SQLite database');
        createTables();
    }
});

function createTables() {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS friends (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        friend_id INTEGER,
        friend_username TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(friend_id) REFERENCES users(id)
    )`, (err) => {
        if (err) {
            console.error('Error creating friends table:', err);
        } else {
            console.log('Friends table created successfully');
            
            db.get(`PRAGMA table_info(friends) WHERE name = 'friend_username'`, (err, row) => {
                if (!row) {
                    db.run('ALTER TABLE friends ADD COLUMN friend_username TEXT', (err) => {
                        if (err) {
                            if (err.errno === 1 && err.code === 'SQLITE_ERROR' && err.message.includes('duplicate column name')) {
                                console.log('friend_username column already exists in friends table');
                            } else {
                                console.error('Error adding friend_username column to friends table:', err);
                            }
                        } else {
                            console.log('Added friend_username column to friends table');
                        }
                    });
                } else {
                    console.log('friend_username column already exists in friends table');
                }
            });
        }
    });

    db.run(`CREATE TABLE IF NOT EXISTS friend_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        receiver_id INTEGER,
        status TEXT,
        sender_username TEXT,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
    )`);

    // Create messages table if not exists
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        receiver_id INTEGER,
        content TEXT,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id)
    )`, (err) => {
        if (err) {
            console.error('Error creating messages table:', err);
        } else {
            console.log('Messages table created successfully');
        }
    });
}


app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
        done(err, row);
    });
});

passport.use(new LocalStrategy(
    function(username, password, done) {
        db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
            if (err) {
                return done(err);
            }
            if (!user) {
                return done(null, false, { message: 'Incorrect username.' });
            }
            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    return done(err);
                }
                if (!result) {
                    return done(null, false, { message: 'Incorrect password.' });
                }
                return done(null, user);
            });
        });
    }
));

app.get('/message', (req, res) => {
    // Check if user is authenticated
    if (!req.isAuthenticated()) {
        return res.redirect('/login'); // Redirect to login page if not authenticated
    }

    const loggedInUserId = req.user.id; // Get the logged-in user's ID

    // Fetch the list of friends for the logged-in user
    db.all('SELECT * FROM friends WHERE user_id = ?', [loggedInUserId], (err, friends) => {
        if (err) {
            console.error('Error fetching friends:', err);
            return res.status(500).send('Internal Server Error');
        }

        // Fetch messages for each friend separately
        const friendMessagesPromises = friends.map(friend => {
            return new Promise((resolve, reject) => {
                const friendId = friend.friend_id;
                db.all('SELECT * FROM messages WHERE (receiver_id = ? AND sender_id = ?) OR (receiver_id = ? AND sender_id = ?) ORDER BY sent_at',
                    [loggedInUserId, friendId, friendId, loggedInUserId],
                    (err, messages) => {
                        if (err) {
                            console.error(`Error fetching messages for friend ${friendId}:`, err);
                            resolve([]);
                        } else {
                            // Update each message to include a flag indicating whether it was sent by the logged-in user
                            messages.forEach(message => {
                                message.sentByLoggedInUser = message.sender_id === loggedInUserId;
                            });
                            resolve(messages);
                        }
                    });
            });
        });

        // Resolve all promises and render the message page with user information, list of friends, and messages
        Promise.all(friendMessagesPromises).then(messagesByFriend => {
            res.render('message', { 
                loggedIn: true, 
                username: req.user.username, 
                friends: friends, 
                messagesByFriend: messagesByFriend, 
                loggedInUserId: loggedInUserId,
                req: req
            });
        }).catch(err => {
            console.error('Error fetching messages for friends:', err);
            return res.status(500).send('Internal Server Error');
        });
    });
});


app.get('/get-messages', (req, res) => {
    // Check if user is authenticated
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const loggedInUserId = req.user.id; // Get the logged-in user's ID
    const recipient = req.query.recipient; // Get the recipient's username from the query parameter

    // Fetch messages between the logged-in user and the specified recipient
    db.all('SELECT id, sender_id, content FROM messages WHERE (sender_id = ? AND receiver_id = (SELECT id FROM users WHERE username = ?)) OR (receiver_id = ? AND sender_id = (SELECT id FROM users WHERE username = ?)) ORDER BY sent_at',
        [loggedInUserId, recipient, loggedInUserId, recipient], (err, messages) => {
            if (err) {
                console.error('Error fetching messages:', err);
                return res.status(500).json({ message: 'Internal Server Error' });
            }

            // Add a property to each message indicating whether it was sent by the logged-in user
            messages.forEach(message => {
                message.sentByLoggedInUser = (message.sender_id === loggedInUserId);
            });

            // Send the fetched messages as a JSON response
            res.json({ messages: messages, loggedInUserId: loggedInUserId });
        });
});



app.post('/send-message', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const { recipient, message } = req.body;
    const senderId = req.user.id;

    // Save the message in the messages table
    db.run('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, (SELECT id FROM users WHERE username = ?), ?)', [senderId, recipient, message], (err) => {
        if (err) {
            console.error('Error sending message:', err);
            return res.status(500).json({ message: 'Internal Server Error' });
        }
    
        // Message sent successfully
        res.status(200).json({ message: 'Message sent successfully' });
    });
});



app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            console.error('Error during authentication:', err);
            return next(err);
        }
        if (!user) {
            req.flash('error', 'Incorrect username or password');
            return res.redirect('/login');
        }
        req.logIn(user, (err) => {
            if (err) {
                console.error('Error during login:', err);
                return next(err);
            }
            return res.redirect('/');
        });
    })(req, res, next);
});


app.get('/create-account', (req, res) => {
    res.render('create_account');
});

app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err.message);
            return res.status(500).send('Internal Server Error');
        }
        res.redirect('/login');
    });
});

app.post('/create-account', async (req, res, next) => {
    const { username, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword], function(err) {
            if (err) {
                console.error('Error creating account:', err);
                return res.status(500).send('Internal Server Error');
            }
            console.log('Account created successfully:', { username, email });
            
            passport.authenticate('local', (err, user, info) => {
                if (err) {
                    return next(err);
                }
                if (!user) {
                    return res.redirect('/login');
                }
                req.logIn(user, (err) => {
                    if (err) {
                        return next(err);
                    }
                    return res.redirect('/');
                });
            })(req, res, next);
        });
    } catch (error) {
        console.error('Error creating account:', error);
        return res.status(500).send('Internal Server Error');
    }
});

async function getOAuthToken() {
    try {
        const response = await axios.post('https://id.twitch.tv/oauth2/token', null, {
            params: {
                client_id: config.client_id,
                client_secret: config.client_secret,
                grant_type: 'client_credentials'
            }
        });
        return response.data.access_token;
    } catch (error) {
        console.error('Error obtaining OAuth token:', error);
        throw error;
    }
}


async function fetchTwitchData() {
    try {
        const token = await getOAuthToken();

        const streamers = require('./pro_fn_streams.json');

        const delayBetweenRequests = 2000;

        for (const streamer of streamers) {
            const response = await axios.get(`https://api.twitch.tv/helix/streams?user_login=${streamer.username}`, {
                headers: {
                    Authorization: `Bearer ${token}`,
                    'Client-ID': config.client_id
                }
            });

            console.log(`Twitch API response for ${streamer.username}:`, response.data);

            await new Promise(resolve => setTimeout(resolve, delayBetweenRequests));
        }
    } catch (error) {
        console.error('Error fetching Twitch data:', error);
    }
}

fetchTwitchData();


passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
        done(err, row);
    });
});

passport.use(new LocalStrategy(
    function(username, password, done) {
        db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
            if (err) {
                return done(err);
            }
            if (!user) {
                return done(null, false, { message: 'Incorrect username.' });
            }
            bcrypt.compare(password, user.password, (err, result) => {
                if (err) {
                    return done(err);
                }
                if (!result) {
                    return done(null, false, { message: 'Incorrect password.' });
                }
                return done(null, user);
            });
        });
    }
));

async function fetchProPlayerStreams() {
    try {
        const response = await fetch('http://localhost:3000/pro-player-streams');
        const proPlayerStreams = await response.json();
        return proPlayerStreams;
    } catch (error) {
        console.error('Error fetching pro player streams:', error);
        throw error;
    }
}

async function updateLiveStatus() {
    try {
        const streamers = await fetchProPlayerStreams();
        for (const streamer of streamers) {
            const isLive = await isStreamerLive(streamer.twitch_channel);
            streamer.is_live = isLive;
        }
        fs.writeFileSync('pro_fn_streams.json', JSON.stringify(streamers, null, 2));
    } catch (error) {
        console.error('Error updating live status:', error);
    }
}

async function isStreamerLive(streamer) {
    try {
        const token = await getOAuthToken();

        const response = await axios.get(`https://api.twitch.tv/helix/streams?user_login=${streamer}`, {
            headers: {
                Authorization: `Bearer ${token}`,
                'Client-ID': config.client_id
            }
        });

        return response.data.data.length > 0;
    } catch (error) {
        console.error('Error checking stream status:', error);
        return false;
    }
}

        setInterval(updateLiveStatus, 60 * 1000);


app.get('/', (req, res) => {
    console.log("Authenticated:", req.isAuthenticated());
    console.log("Username:", req.user ? req.user.username : null);
    const accountCreated = req.query.accountCreated === 'true';
    res.render('index', { loggedIn: req.isAuthenticated(), username: req.user ? req.user.username : null, accountCreated });
});

app.get('/pro-player-streams', (req, res) => {
    fs.readFile('pro_fn_streams.json', (err, data) => {
        if (err) {
            console.error('Error reading pro player streams JSON file:', err);
            res.status(500).send('Error reading pro player streams JSON file');
            return;
        }
        const proPlayerStreams = JSON.parse(data);
        res.json(proPlayerStreams);
    });
});

app.get('/stats', (req, res) => {
    res.render('stats_input', { loggedIn: req.isAuthenticated(), username: req.user ? req.user.username : null });
});

app.get('/profile', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }

    const userId = req.user.id;

    db.all('SELECT * FROM friends WHERE user_id = ?', [userId], (err, friends) => {
        if (err) {
            console.error('Error fetching friends:', err);
            return res.status(500).send('Internal Server Error');
        }

        db.all('SELECT * FROM friend_requests WHERE receiver_id = ? AND status = ?', [userId, 'pending'], (err, pendingFriendRequests) => {
            if (err) {
                console.error('Error fetching pending friend requests:', err);
                return res.status(500).send('Internal Server Error');
            }

            const posts = [];

            res.render('profile', {
                loggedIn: req.isAuthenticated(),
                username: req.user.username,
                friends: friends,
                pendingFriendRequests: pendingFriendRequests,
                posts: posts
            });
        });
    });
});

app.post('/add-friend', async (req, res) => {
    const { friendUsername } = req.body;
    const senderId = req.user.id;
    const senderUsername = req.user.username;

    try {
        if (friendUsername === senderUsername) {
            return res.status(400).json({ message: 'Cannot add yourself as a friend' });
        }

        const receiver = await getUserByUsername(friendUsername);
        if (!receiver) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isAlreadyFriend = await checkFriendshipExists(senderId, receiver.id);
        if (isAlreadyFriend) {
            return res.status(400).json({ message: 'User is already your friend' });
        }

        const pendingRequestFromRequester = await checkPendingRequestExists(senderId, receiver.id);
        if (pendingRequestFromRequester) {
            return res.status(400).json({ message: 'Pending friend request already sent to this user' });
        }

        const pendingRequestToRequester = await checkPendingRequestExists(receiver.id, senderId);
        if (pendingRequestToRequester) {
            return res.status(400).json({ message: 'You have a pending friend request from this user' });
        }

        const status = 'pending';
        await new Promise((resolve, reject) => {
            db.run('INSERT INTO friend_requests (sender_id, sender_username, receiver_id, status) VALUES (?, ?, ?, ?)', [senderId, senderUsername, receiver.id, status], (err) => {
                if (err) {
                    console.error('Error sending friend request:', err);
                    reject(err);
                } else {
                    sendFriendRequestNotification(receiver.id, senderUsername);
                    resolve();
                }
            });
        });

        res.json({ message: 'Friend request sent successfully' });

    } catch (error) {
        console.error('Error adding friend:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
});

async function checkPendingRequestExists(senderId, receiverId) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM friend_requests WHERE sender_id = ? AND receiver_id = ? AND status = "pending"', [senderId, receiverId], (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row !== undefined);
            }
        });
    });
}

async function checkFriendshipExists(userId1, userId2) {
    return new Promise((resolve, reject) => {
        db.get('SELECT COUNT(*) AS count FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)', [userId1, userId2, userId2, userId1], (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row.count > 0);
            }
        });
    });
}

function sendFriendRequestNotification(receiverId, senderUsername) {
   

    console.log(`Notification: You have received a friend request from ${senderUsername}`);
}

function openAddFriendPopup() {
    document.getElementById('addFriendPopup').style.display = 'block';
}

app.get('/friend-requests', (req, res) => {
    db.all('SELECT * FROM friend_requests WHERE receiverId = ? AND status = ?', [req.user.id, 'pending'], (err, friendRequests) => {
        if (err) {
            console.error('Error fetching friend requests:', err);
            return res.status(500).send('Internal Server Error');
        }
        res.render('friend_requests', { friendRequests });
    });
});

function addFriend(userId1, userId2, res, redirectUrl) {
    db.run('INSERT INTO friends (user_id, friend_id, friend_username) VALUES (?, ?, (SELECT username FROM users WHERE id = ?))', [userId1, userId2, userId2], (err1) => {
        if (err1) {
            console.error('Error adding friend to user1\'s friend list:', err1);
            return res.status(500).send('Internal Server Error');
        }

        db.run('INSERT INTO friends (user_id, friend_id, friend_username) VALUES (?, ?, (SELECT username FROM users WHERE id = ?))', [userId2, userId1, userId1], (err2) => {
            if (err2) {
                console.error('Error adding friend to user2\'s friend list:', err2);
                return res.status(500).send('Internal Server Error');
            }

            res.redirect(redirectUrl);
        });
    });
}

app.post('/accept-friend-request', (req, res) => {
    const { requestId } = req.body;

    db.get('SELECT * FROM friend_requests WHERE id = ?', [requestId], (err, friendRequest) => {
        if (err) {
            console.error('Error retrieving friend request:', err);
            return res.status(500).send('Internal Server Error');
        }
        if (!friendRequest || friendRequest.status !== 'pending') {
            console.error('Invalid friend request');
            return res.status(400).send('Invalid friend request');
        }

        const senderId = friendRequest.sender_id;
        const receiverId = friendRequest.receiver_id;

        db.run('UPDATE friend_requests SET status = ? WHERE id = ?', ['accepted', requestId], (err) => {
            if (err) {
                console.error('Error updating friend request status:', err);
                return res.status(500).send('Internal Server Error');
            }

            addFriend(senderId, receiverId, res, '/profile');
        });
    });
});

app.post('/decline-friend-request', (req, res) => {
    const requestId = req.body.requestId;

    db.run('DELETE FROM friend_requests WHERE id = ?', [requestId], (err) => {
        if (err) {
            console.error('Error declining friend request:', err);
            return res.status(500).send('Internal Server Error');
        }

        res.redirect('/profile');
    });
});


app.post('/respond-friend-request', (req, res) => {
    const { requestId, response } = req.body;

    db.run('UPDATE friend_requests SET status = ? WHERE id = ?', [response, requestId], (err) => {
        if (err) {
            console.error('Error responding to friend request:', err);
            return res.status(500).send('Internal Server Error');
        }

        res.redirect('/friend-requests');
    });
});

app.get('/settings', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    res.render('settings', { loggedIn: req.isAuthenticated(), username: req.user ? req.user.username : null, email: req.user ? req.user.email : null });
});

app.post('/settings', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    
    const { currentPassword, newPassword } = req.body;
    const email = req.user.email;

    try {
        const user = await getUserByEmail(email);

        const passwordMatch = await bcrypt.compare(currentPassword, user.password);

        if (!passwordMatch) {
            return res.redirect('/settings?error=currentPasswordIncorrect');
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await updateUserPassword(email, hashedPassword);

        return res.redirect('/settings?success=passwordChanged');
    } catch (error) {
        console.error('Error changing password:', error);
        return res.status(500).send('Internal Server Error');
    }
});

function getUserByUsername(username) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
            if (err) {
                reject(err);
            } else {
                resolve(user);
            }
        });
    });
}

function getUserByEmail(email) {
    return new Promise((resolve, reject) => {
        db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
            if (err) {
                return reject(err);
            }
            resolve(row);
        });
    });
}

function updateUserPassword(email, newPassword) {
    return new Promise((resolve, reject) => {
        db.run('UPDATE users SET password = ? WHERE email = ?', [newPassword, email], function(err) {
            if (err) {
                return reject(err);
            }
            resolve();
        });
    });
}

app.post('/stats', async (req, res) => {
    try {
        const { username, platform } = req.body;
        const playerStats = await fetchPlayerStats(username, platform);
        res.render('stats', { playerStats });
    } catch (error) {
        console.error("Error fetching player stats:", error);
        res.status(500).send("Error fetching player stats");
    }
});

app.get('/shop', async (req, res) => {
    try {
        const featuredItems = await fetchShopItems();
        res.render('shop', { featuredItems, loggedIn: req.isAuthenticated(), username: req.user ? req.user.username : null });
    } catch (error) {
        console.error("Error fetching shop items:", error);
        res.status(500).send("Error fetching shop items");
    }
});

async function fetchShopItems() {
    try {
        const url = 'https://fnbr.co/api/shop';
        const fnbr_apiKey = config.FNBR_API_KEY;
        const options = {
            headers: {
                'x-api-key': fnbr_apiKey
            }
        };
        const response = await axios.get(url, options);
        return response.data.data.featured.filter(item => !item.images.icon.includes("lego-outfit") && !item.images.icon.includes("bass") && !item.images.icon.includes("microphone"));
    } catch (error) {
        console.error('Error fetching shop items:', error);
        throw error;
    }
}

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
