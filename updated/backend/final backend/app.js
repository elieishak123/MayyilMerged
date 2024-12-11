const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const nodemailer = require('nodemailer');
const path = require('path');
const crypto = require('crypto');
const cookieParser= require('cookie-parser');
require('dotenv').config();

const app = express();

// Middleware setup
app.use(express.json());
app.use(cors({
  origin: [
    'https://mayyil-aa-libnen-production.up.railway.app/',
    'https://mayyilaalibnen.up.railway.app', // Frontend Railway URL
    'https://mayyilaalibnen.netlify.app',
    'http://localhost:3000', // For local testing
  ],
  credentials: true
}));

app.use(cookieParser());


// Static files from frontend
app.use(express.static(path.join(__dirname, '../frontend')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// MySQL connection setup
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10, // Maximum number of connections in the pool
  queueLimit: 0,
});

db.getConnection((err, connection) => {
  if (err) {
      console.error('Error connecting to the database:', err);
  } else {
      console.log('Connected to the database!');
      connection.release(); // Release the connection back to the pool
  }
});

const JWT_SECRET = process.env.JWT_SECRET;

// Nodemailer transporter setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// OTP storage (in-memory)
let otpStore = {};


// Routes
// Signup with OTP
let processingSignup = {}; // Store per-email processing state

app.post('/signup', async (req, res) => {
    const { email, password, username } = req.body;
    console.log("Received signup request:", req.body);

    // Prevent duplicate requests for the same email
    if (processingSignup[email]) {
        console.log("Signup request already being processed for:", email);
        return res.status(429).json({ message: 'Signup already in progress. Please wait.' });
    }

    processingSignup[email] = true;

    try {
        // Check if the email exists
        const query = 'SELECT * FROM users WHERE email = ?';
        db.query(query, [email], async (err, results) => {
            if (err) {
                console.error("Database error during email check:", err);
                delete processingSignup[email];
                return res.status(500).json({ message: 'Database error' });
            }

            if (results.length > 0) {
                console.log("Email already exists:", email);
                delete processingSignup[email];
                return res.status(400).json({ message: 'Email already exists' });
            }

            // Insert user into the database
            const hashedPassword = await bcrypt.hash(password, 10);
            const insertQuery = 'INSERT INTO users (email, password, username) VALUES (?, ?, ?)';
            db.query(insertQuery, [email, hashedPassword, username], async (err) => {
                if (err) {
                    console.error("Database error during user insertion:", err);
                    delete processingSignup[email];
                    return res.status(500).json({ message: 'Database error' });
                }

                console.log("User inserted into database successfully.");

                // Generate and send OTP
                const otp = Math.floor(1000 + Math.random() * 9000).toString();
                otpStore[email] = otp;

                const mailOptions = {
                    from: process.env.EMAIL_USER,
                    to: email,
                    subject: 'Your OTP Code',
                    text: `Your OTP code is: ${otp}`,
                };

                try {
                    await transporter.sendMail(mailOptions);
                    console.log("OTP sent to email successfully.");
                    delete processingSignup[email]; // Reset processing flag
                    return res.status(201).json({ message: 'User created successfully. OTP sent to email.' });
                } catch (emailError) {
                    console.error("Error sending OTP email:", emailError);
                    delete processingSignup[email]; // Reset processing flag
                    return res.status(500).json({ message: 'Error sending OTP email' });
                }
            });
        });
    } catch (error) {
        console.error("Unexpected error during signup:", error);
        delete processingSignup[email]; // Reset processing flag
        return res.status(500).json({ message: 'Internal server error' });
    }
});
function authenticateUser(req, res, next) {
  console.log('Cookies received:', req.cookies); // Log all cookies

  const token = req.cookies.authToken;
  console.log('Token received:', token); // Log the specific token

  if (!token) {
      console.log('No token provided');
      return res.status(401).json({ message: 'Unauthorized: No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
          console.log('Token verification failed:', err.message); // Log token verification errors
          return res.status(403).json({ message: 'Unauthorized: Invalid token' });
      }
      console.log('Token decoded:', decoded); // Log decoded token info
      req.user = decoded; // Attach decoded token to the request
      next();
  });
}



app.get('/verify-token', (req, res) => {
  const token = req.cookies.authToken;

  console.log('Cookies received:', req.cookies);
  console.log('Auth token received:', token);

  if (!token) {
      return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
          console.error('JWT verification failed:', err);
          return res.status(403).json({ message: 'Invalid or expired token' });
      }

      console.log('Decoded token:', decoded);
      res.status(200).json({ isLoggedIn: true, userId: decoded.id });
  });
});



// Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, results) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      if (results.length === 0) return res.status(400).json({ message: 'Invalid email or password' });

      const user = results[0];
      bcrypt.compare(password, user.password, (err, isMatch) => {
          if (err) return res.status(500).json({ message: 'Error comparing passwords' });
          if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

          // Generate token
          const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });

          // Set token in cookie
          res.cookie('authToken', token, {
              httpOnly: true, // Prevents client-side scripts from accessing the cookie
              secure: true, // Ensures cookies are sent over HTTPS
              maxAge: 1000 * 60 * 60 * 24 * 30, // 30 days
              sameSite: 'None', // Allows cross-origin requests
              path: "/", // Makes the cookie available across the site
          });
        

          console.log('Cookie set: authToken=', token);

          // Send success response
          res.status(200).json({ message: 'Login successful' });
      });
  });
});

// Logout endpoint to clear cookies
app.post('/logout', (req, res) => {
  res.clearCookie('authToken', {
    httpOnly: true,
    secure: true, // Match secure setting from /login
    sameSite: 'None',
    path: "/"
  });
  
  

  res.status(200).json({ message: 'Logged out successfully' });
});
// for the users info
const authenticateToken = (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) return res.status(403).json({ message: 'Invalid token' });

      req.user = user; // Save the user info (e.g., ID, email) in the request object
      next();
  });
};
app.get('/user/data', authenticateToken, (req, res) => {
  const userId = req.user.id; // Extracted from the token
  
  const query = 'SELECT * FROM users WHERE id = ?';
  db.query(query, [userId], (err, results) => {
      if (err) return res.status(500).json({ message: 'Database error' });
      if (results.length === 0) return res.status(404).json({ message: 'User not found' });

      res.status(200).json(results[0]); // Return user data
  });
});

// Forgot Password - Send Reset Link
app.post('/forgot-password', (req, res) => {
  const { email } = req.body;

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (results.length === 0) return res.status(400).json({ message: 'Email not found' });

    const resetToken = jwt.sign({ email: results[0].email }, JWT_SECRET, { expiresIn: '15m' });

    // Use the updated backend URL for the reset password link
    const resetLink = `https://mayyilaalibnen.netlify.app/reset-password?token=${resetToken}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset Request',
      text: `Click on this link to reset your password: ${resetLink}`
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) return res.status(500).json({ message: 'Error sending email' });
      res.json({ message: 'Password reset link has been sent to your email' });
    });
  });
});

// Password Reset
app.post('/reset-password', (req, res) => {
  const { token, password } = req.body;

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    const email = decoded.email;
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        return res.status(500).json({ message: 'Error hashing the password' });
      }

      const query = 'UPDATE users SET password = ? WHERE email = ?';
      db.query(query, [hashedPassword, email], (err) => {
        if (err) {
          return res.status(500).json({ message: 'Database error' });
        }
        res.json({ message: 'Password successfully reset' });
      });
    });
  });
});


// Update the path to an absolute path directly to the updated/frontend directory
// Replace this with the absolute path to the frontend directory on your machine
app.get('/reset-password', (req, res) => {
  const token = req.query.token;

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(400).send('Invalid or expired token');
    }

    const filePath = path.join(__dirname, '../frontend/reset-password.html');
    res.sendFile(filePath, {
      headers: {
        'Cache-Control': 'no-store'
      }
    });
  });
});

// OTP Request
app.post("/request-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email is required" });

  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  otpStore[email] = otp;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Your OTP Code",
    text: `Your OTP code is: ${otp}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ message: "OTP sent successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error sending OTP" });
  }
});

// OTP Verification
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
      console.log("Missing email or OTP in request.");
      return res.status(400).json({ success: false, message: "Email and OTP are required" });
  }

  console.log("Verifying OTP for email:", email, "with OTP:", otp);

  if (otpStore[email]) {
      if (otpStore[email] === otp) {
          console.log("OTP verified successfully for email:", email);
          delete otpStore[email]; // Clear OTP after successful verification
          return res.json({ success: true, message: "OTP verified successfully" });
      } else {
          console.log("Invalid OTP entered for email:", email, "Expected:", otpStore[email]);
          return res.status(400).json({ success: false, message: "Invalid OTP" });
      }
  } else {
      console.log("No OTP found for email:", email);
      return res.status(400).json({ success: false, message: "No OTP found for this email" });
  }
});

app.get('/test-insert', (req, res) => {
  const testEmail = "test@example.com";
  const testPassword = "testpassword";
  const testUsername = "testuser";

  const query = 'INSERT INTO users (email, password, username) VALUES (?, ?, ?)';
  db.query(query, [testEmail, testPassword, testUsername], (err) => {
    if (err) {
      console.error("Test insertion error:", err);
      return res.status(500).json({ message: "Test insertion failed", error: err.message });
    }
    res.json({ message: "Test insertion succeeded" });
  });
});


// Serve OTP and Reset Password Pages
app.get('/otp', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/emailotp.html'));
});

// Add an area to the planner
app.post('/api/planner', authenticateUser, (req, res) => {
  const userId = req.user.id; // Retrieved from the authenticated token
  const { areaId } = req.body;

  if (!areaId) {
    return res.status(400).json({ message: 'Area ID is required.' });
  }

  const query = 'INSERT INTO planner (user_id, area_id, added_at) VALUES (?, ?, NOW())';
  db.query(query, [userId, areaId], (err) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ message: 'Failed to add area to planner.' });
    }
    res.status(200).json({ message: 'Area added to planner successfully!' });
  });
});

// Get all planner items for a user
app.get('/api/planner', authenticateUser, (req, res) => {
  const userId = req.user.id;
  console.log('Fetching planner data for user ID:', userId); // Debug log

  const query = `
    SELECT areas.area_name, planner.area_id, planner.added_at 
    FROM planner 
    JOIN areas ON planner.area_id = areas.area_id 
    WHERE planner.user_id = ?
  `;

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error fetching planner data:', err);
      return res.status(500).json({ message: 'Failed to fetch planner data.' });
    }

    res.status(200).json(results);
  });
});

// Remove a specific area from the planner
app.delete('/api/planner', authenticateUser, (req, res) => {
  const userId = req.user.id;
  const { areaId } = req.body;

  if (!areaId) {
    return res.status(400).json({ message: 'Area ID is required.' });
  }

  const query = 'DELETE FROM planner WHERE user_id = ? AND area_id = ?';
  db.query(query, [userId, areaId], (err) => {
    if (err) {
      console.error('Error deleting planner item:', err);
      return res.status(500).json({ message: 'Failed to remove area from planner.' });
    }

    res.status(200).json({ message: 'Area removed from planner successfully.' });
  });
});

// Clear all planner items for a user
app.delete('/api/planner/clear', authenticateUser, (req, res) => {
  const userId = req.user.id;

  const query = 'DELETE FROM planner WHERE user_id = ?';
  db.query(query, [userId], (err) => {
    if (err) {
      console.error('Error clearing planner:', err);
      return res.status(500).json({ message: 'Failed to clear planner.' });
    }

    res.status(200).json({ message: 'Planner cleared successfully.' });
  });
});


const queryPromise = (sql, params) => {
  return new Promise((resolve, reject) => {
      db.query(sql, params, (err, results) => {
          if (err) return reject(err);
          resolve(results);
      });
  });
};

// POST: Add a review
app.post('/api/reviews', authenticateUser, (req, res) => {
  const { areaId, review, rating } = req.body;

  if (!areaId || !review || !rating) {
      return res.status(400).json({ message: 'Area ID, review, and rating are required.' });
  }

  const userId = req.user.id; // Assuming `authenticateUser` middleware sets `req.user`

  const query = `
      INSERT INTO reviews (area_id, user_id, review, rating)
      VALUES (?, ?, ?, ?)
  `;

  db.query(query, [areaId, userId, review, rating], (err, result) => {
      if (err) {
          console.error('Error inserting review:', err);
          return res.status(500).json({ message: 'Failed to add review.' });
      }

      res.status(201).json({ message: 'Review added successfully!' });
  });
});


// GET: Fetch reviews for a specific area
app.get('/api/reviews', authenticateUser, (req, res) => {
  const areaId = req.query.area_id;

  if (!areaId) {
      return res.status(400).json({ message: 'Area ID is required' });
  }

  const query = `
      SELECT reviews.review_id, reviews.review, reviews.rating, users.username, reviews.user_id
      FROM reviews
      JOIN users ON reviews.user_id = users.id
      WHERE reviews.area_id = ?
  `;

  db.query(query, [areaId], (err, results) => {
      if (err) {
          console.error('Database error fetching reviews:', err);
          return res.status(500).json({ message: 'Failed to fetch reviews' });
      }

      console.log("Fetched Reviews:", results); // Debug log
      res.status(200).json({
          reviews: results,
          currentUserId: req.user.id
      });
  });
});


// GET: Fetch area details
app.get("/api/areas/:area_id", async (req, res) => {
  const { area_id } = req.params;
  console.log("Requested Area ID:", area_id); // Debug log

  try {
      const area = await queryPromise(
          "SELECT area_id, area_name, city FROM areas WHERE area_id = ?", // Corrected column names
          [area_id]
      );
      console.log("Fetched Area Data:", area); // Debug log
      if (area.length === 0) {
          return res.status(404).json({ message: "Area not found" });
      }
      res.json(area[0]); // Return the first matching area
  } catch (error) {
      console.error("Error fetching area details:", error);
      res.status(500).json({ message: "Failed to fetch area details" });
  }
});



// PUT: Update a review
app.put('/api/reviews/:reviewId', authenticateUser, (req, res) => {
  const userId = req.user.id;
  const { reviewId } = req.params;
  const { review, rating } = req.body;

  if (!review || !rating) {
      return res.status(400).json({ message: 'Review and rating are required.' });
  }
  if (rating < 1 || rating > 5) {
      return res.status(400).json({ message: 'Rating must be between 1 and 5.' });
  }

  const query = `
      UPDATE reviews
      SET review = ?, rating = ?
      WHERE review_id = ? AND user_id = ?
  `;
  db.query(query, [review, rating, reviewId, userId], (err, results) => {
      if (err) {
          console.error('Error updating review:', err);
          return res.status(500).json({ message: 'Failed to update review.' });
      }

      if (results.affectedRows === 0) {
          return res.status(403).json({ message: 'You can only edit your own reviews.' });
      }

      res.status(200).json({ message: 'Review updated successfully.' });
  });
});

// DELETE: Delete a review
app.delete('/api/reviews/:reviewId', authenticateUser, (req, res) => {
  const userId = req.user.id; // Current logged-in user's ID
  const userEmail = req.user.email; // Current logged-in user's email
  const { reviewId } = req.params;

  console.log("Deleting review with ID:", reviewId); // Debugging
  console.log("User attempting delete:", { userId, userEmail }); // Debugging

  // Check if the user is the super user
  const isSuperUser = userEmail === 'elieishak100@gmail.com';

  // If the user is a super user, allow them to delete any review
  const query = isSuperUser
      ? `DELETE FROM reviews WHERE review_id = ?` // Super user can delete any review
      : `DELETE FROM reviews WHERE review_id = ? AND user_id = ?`; // Normal users can only delete their reviews

  const queryParams = isSuperUser ? [reviewId] : [reviewId, userId];

  db.query(query, queryParams, (err, results) => {
      if (err) {
          console.error("Error deleting review:", err);
          return res.status(500).json({ message: "Failed to delete review." });
      }

      if (results.affectedRows === 0) {
          return res.status(403).json({ message: isSuperUser ? "Review not found." : "You can only delete your own reviews." });
      }

      res.status(200).json({ message: "Review deleted successfully." });
  });
});

app.get('/test-connection', (req, res) => {
  console.log('Test connection endpoint hit');
  res.status(200).json({ message: 'Backend is working correctly!' });
});



app.get('/test-cookie', (req, res) => {
  console.log('Cookies:', req.cookies);
  res.json({ message: 'Cookie check successful', cookies: req.cookies });
});

// Start server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
