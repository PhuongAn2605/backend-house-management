const express = require('express');
const replyLike = require('../controllers/replyLike.controllers');

const router = express.Router();

router.post('/', replyLike.likeReact);

module.exports = router;