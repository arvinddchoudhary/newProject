const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;

// Middleware to parse JSON requests
app.use(express.json());

// In-memory data store
const users = [];
const todos = [];

// Secret key for JWT
const SECRET_KEY = 'your_secret_key';

// Root route
app.get('/', (req, res) => {
  res.send('Welcome to the To-Do API!');
});
// changes made by arvind
//again changes made by arvind second second time
// Signup endpoint
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if username and password are provided
    if (!username || !password) {
      return res.status(400).send('Username and password are required');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store the user
    users.push({ username, password: hashedPassword });

    res.status(201).send('User registered');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find the user
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(401).send('Invalid credentials');
    }

    // Compare passwords
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).send('Invalid credentials');
    }

    // Generate JWT
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
};

// Create a new to-do item
app.post('/todos', authenticateJWT, (req, res) => {
  const { task } = req.body;
  if (!task) {
    return res.status(400).send('Task is required');
  }
  todos.push({ username: req.user.username, task });
  res.status(201).send('To-do item created');
});

// Get all to-do items for the logged-in user
app.get('/todos', authenticateJWT, (req, res) => {
  const userTodos = todos.filter(todo => todo.username === req.user.username);
  res.json(userTodos);
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});