const express = require('express');
const notificationCOntrollers = require('../controllers/notification.controllers');

const router = express.Router();

router.get('/last-login/:userId', notificationCOntrollers.getLastLogin);

module.exports = router;