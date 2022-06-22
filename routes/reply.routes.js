const express = require('express');

const replyController = require('../controllers/reply.controllers');

const router = express.Router();

router.get('/:cid', replyController.getReplyByCommentId);

router.post('/create/:cid', replyController.createReply);

router.patch('/edit/:rid', replyController.editReply);

router.delete('/delete/:rid', replyController.deleteReply);

module.exports = router;