const { validationResult } = require("express-validator");
const isEmpty = require("is-empty");
const Comment = require("../models/Comment");
const HttpError = require("../models/http-error");
const Product = require("../models/Product");
const Reply = require("../models/Reply");

const getReplyByCommentId = async (req, res, next) => {
    const commentId = req.params.cid;
  let comment;
  let targetReplies;
  try {
    // reply = await Reply.find({ productId: productId, houseId: houseId });
    comment = await Comment.findById(commentId);
    if (isEmpty(comment)) {
      return next(new HttpError("Could not find any reply", 400));
    }
    const repliesOfComment = await comment.populate('replyComments');
    targetReplies = repliesOfComment.replyComments;

  } catch (err) {
    console.log(err);
    return next(new HttpError("Something went wrong", 500));
  }
  res.status(200).json({ replyComments: targetReplies });
};

const createReply = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(new HttpError("Invalid data passed", 422));
  }

  const commentId = req.params.cid;
  const { content, commenter } = req.body;

  const createdReply = new Reply({
    content,
    commenter,
    commentId,
  });

  let targetComment;

  try {
    targetComment = await Comment.findById(commentId);

    const saveReply = await createdReply.save();
    if (isEmpty(saveReply)) {
      return next(new HttpError("Could not save the product", 500));
    }

    targetComment.replyComments.push(saveReply);
    await targetComment.save();
  } catch (err) {
    console.log(err);
    return next(new HttpError("Something went wrong, could not reply", 500));
  }

  const repliesOfComment = await targetComment.populate('replyComments');
  const targetReplies = repliesOfComment.replyComments;

  res.status(201).json({ replyComments: targetReplies });
};

const editReply = async (req, res) => {
  const { content } = req.body;
  const replyId = req.params.rid;

  let reply;
  try{
    reply = await Reply.findById(replyId);
    if(isEmpty(reply)){
      return res.status(400).send("Could not find any reply with provided id!");
    }
    reply.content = content;
    const saveReply = await reply.save();
    if(isEmpty(saveReply)){
      return res.status(500).send("Could not save the reply!");
    }

  }catch(err){
    return res.status(500).send("Something went wrong");
  }
  res.status(200).json({ reply: reply })

}

const deleteReply = async (req, res) => {
  const replyId = req.params.rid;
  let reply;


  try{
    reply = await Reply.findById(replyId).populate("commentId");
    console.log(reply)
    if(isEmpty(reply)){
      return res.status(404).send("Could not find the reply with provied id!");
    }
    const deleteReply = await reply.remove();
    if(isEmpty(deleteReply)){
      return res.status(500).send("Could not delete the reply!");
    }
    reply.commentId.replyComments.pull(reply);
    await reply.commentId.save();

  }catch(error){
    console.log(error)
    return res.status(500).send("Something went wrong");
  }
  res.status(200).send("Deleted the reply!");
}

exports.createReply = createReply;
exports.getReplyByCommentId = getReplyByCommentId;
exports.editReply = editReply;
exports.deleteReply = deleteReply;
