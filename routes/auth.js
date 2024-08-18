const express= require('express');

const router = express.Router();

const {login , register , forgotPassword, resetPassword, logout} = require('../controllers/auth');

router.post('/register',register);
router.post('/login' , login);
router.post('/forget_password' , forgotPassword);
router.post('/reset_password' , resetPassword);
router.get('/logout' , logout);    

module.exports = router;