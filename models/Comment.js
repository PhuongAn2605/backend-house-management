const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const commentSchema = new Schema(
  {
    houseId: { type: mongoose.Types.ObjectId, required: true, ref: "House" },
    content: { type: String, required: true },
    commenter: { type: String },
    commentLikes: [{ type: mongoose.Types.ObjectId, ref: "CommentLike" }],
    replyComments: [{ type: mongoose.Types.ObjectId, ref: "Reply" }],
  },
  { timestamps: true }
);

module.exports = mongoose.model("Comment", commentSchema);
