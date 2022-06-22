const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const replyLikeSchema = new Schema({

    replyId: {type: mongoose.Types.ObjectId, required: true, ref:'Reply'},
    userName: { type: String, required: true }
});

module.exports = mongoose.model('ReplyLike', replyLikeSchema);