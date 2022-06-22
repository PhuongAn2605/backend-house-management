const express = require('express');
const commentLikeControllers = require('../controllers/commentLike.controllers');

const router = express.Router();

router.post('/:commentId', commentLikeControllers.likeReact);

module.exports = router;