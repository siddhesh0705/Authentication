const jwt = require('jsonwebtoken');
const { UnauthenticatedError } = require('../errors');

const auth = (req, res, next) => {
  let token;

  // Check if the token exists in cookies
  if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
  }
  // If not in cookies, check Authorization header
  else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  }

  // If no token is found, throw an error
  if (!token) {
    throw new UnauthenticatedError('Authentication invalid');
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    // Attach the user to the request object
    req.user = { userId: payload.userId, name: payload.name };

    next(); // Proceed to the next middleware or route handler
  } catch (error) {
    throw new UnauthenticatedError('Authentication invalid');
  }
};

module.exports = auth;
    