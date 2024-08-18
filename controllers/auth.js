const User = require('../model/User');
const { StatusCodes } = require('http-status-codes');
const { BadRequestError, UnauthenticatedError } = require('../errors');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const {sendEmail} = require('../utils/sendEmail');
const crypto = require('crypto');
const { Op } = require('sequelize');

// Register a new user
const register = async (req, res) => {
  try {
    const user = await User.create({ ...req.body });
    const token = user.createJWT();
    res.status(StatusCodes.CREATED).json({ user: { name: user.getName() }, token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: 'Error registering user', error });
  }
};

// Login user
const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(StatusCodes.BAD_REQUEST).json({ message: 'Email and password are required' });
  }

  try {
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(StatusCodes.UNAUTHORIZED).json({ message: 'Invalid username or password' });
    }

    const token = user.createJWT();

    res.cookie('token', token, {
      httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
      secure: process.env.NODE_ENV === 'production', // Send cookie over HTTPS in production
      sameSite: 'Strict', // Ensures the cookie is only sent over HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    res.status(StatusCodes.OK).json({ user: { name: user.name }, message: 'Login successful' });

  } catch (error) {
    console.error('Login error:', error);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: 'Internal server error' });
  }
};

// Logout user
const logout = (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
  });
  res.status(StatusCodes.OK).json({ message: 'Logout successful' });
};

// Forgot password - Send OTP
const forgotPassword = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(StatusCodes.BAD_REQUEST).json({ message: 'Email field is required' });
  }

  try {

    console.log(`email is ${email}`);

    const user = await User.findOne({ email:email.toLowerCase(  ) });

    if (!user) {
      return res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found' });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const otpExpiration = new Date(Date.now() + process.env.OTP_EXPIRATION * 60000);

    user.otp = otp;
    user.otpExpiration = otpExpiration;
    await user.save();

    await sendEmail(user.email, 'Password Reset OTP', `Your OTP is: ${otp}`); 

    return res.status(StatusCodes.OK).json({ message: 'OTP has been sent to your email.' });

  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: 'Server error', error });
  }
};

// Reset password
const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res.status(StatusCodes.BAD_REQUEST).json({ message: 'Email, OTP, and new password are required' });
  }

  try {
    const user = await User.findOne({
      where: {
        email,
        otp,
        otpExpiration: {
          [Op.gt]: new Date(),
        },
      },
    });

    if (!user) {
      return res.status(StatusCodes.BAD_REQUEST).json({ message: 'Invalid OTP or OTP expired' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, parseInt(process.env.BCRYPT_SALT_ROUNDS));
    await user.update({ password: hashedPassword, otp: null, otpExpiration: null });

    return res.status(StatusCodes.OK).json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: 'Server error', error });
  }
};

module.exports = {
  register,
  login,
  forgotPassword,
  resetPassword,
  logout,
};
