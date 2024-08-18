const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config();

const app = express();
app.use(express.json());

// Import routes
const authRouter = require('./routes/auth');
// const chatRouter = require('./routes/chat');
// const teamRouter = require('./routes/team');

// Import middleware
const notFoundMiddleware = require('./middleware/not-found');
const errorHandlerMiddleware = require('./middleware/error-handler');

// Use routes
app.use('/api/v1/auth', authRouter);
// app.use('/api/v1/chat', chatRouter);
// app.use('/api/v1/team', teamRouter);

// Use middleware
app.use(notFoundMiddleware);
app.use(errorHandlerMiddleware);

// Create HTTP server
const server = http.createServer(app);

// Connect to the database
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to the database...');
  } catch (error) {
    console.error('Database connection error:', error);
    process.exit(1); // Exit process with failure
  }
};

// Start the server
const start = async () => {
  try {
    await connectDB();
    const port = process.env.PORT || 5000;

    server.listen(port, () => {
      console.log(`Server is listening on http://localhost:${port}`); // Corrected log statement
    });

  } catch (error) {
    console.error('Server start error:', error);
    process.exit(1); // Exit process with failure
  }
};

start();
