const Controller = require('../../controllers/auth.controller');
const { Router } = require('express');

const router = Router();

router.post('/subscribe', Controller.subscribe);
router.post('/signup', Controller.signup);
router.post('/login', Controller.login);
router.get('/logout', Controller.logout);
router.post('/forgot-password', Controller.forgotPassword);
router.get('/token', Controller.getToken);
router.get('/user-info', Controller.getUserInfo);
router.patch('/user-info', Controller.updateUserInfo);

module.exports = exports = router;
