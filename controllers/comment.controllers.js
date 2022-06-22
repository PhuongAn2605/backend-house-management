const { validationResult } = require("express-validator");
const isEmpty = require("is-empty");
const Comment = require("../models/Comment");
const HttpError = require("../models/http-error");
const Product = require("../models/Product");
const House = require("../models/House");

const getComment = async (req, res, next) => {
  let comment;
  try {
    // comment = await Comment.find({ productId: productId, houseId: houseId });
    comment = await Comment.find({});
    if (isEmpty(comment)) {
      return next(new HttpError("Could not find any comment", 400));
    }
  } catch (err) {
    console.log(err);
    return next(new HttpError("Something went wrong", 500));
  }
  res.status(200).json({ comment: comment.content, message: "Get comment successfully!" });
};

const createComment = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(new HttpError("Invalid data passed", 422));
  }

  const houseId = req.params.hid;

  const { content, commenter } = req.body;

  const house = await House.findById(houseId);
  let targetComments = [];

  const createdComment = new Comment({
    houseId,
    content,
    commenter,
    commentLike: [],
    replyComments: []
  });

  try {
    const saveComment = await createdComment.save();
    if (isEmpty(saveComment)) {
      return next(new HttpError("Could not save the product", 500));
    }
    house.comments.push(saveComment);
    await house.save();

    targetComments = await Comment.find({ houseId: houseId });
  } catch (err) {
    return next(
      new HttpError("Something went wrong, could not make a comment", 500)
    );
  }

  res.status(201).json({ comments: targetComments, message: "Create comment successfully!" });
};

const getCommentsByHouseId = async (req, res, next) => {
  const houseId = req.params.hid;
  let houseWithComments;
  try {
    houseWithComments = await House.findById(houseId).populate(
      "comments"
    );
    if (!houseWithComments || houseWithComments.comments.length === 0) {
      return next(
        new HttpError("Could not find comments for provided house id", 404)
      );
    }
  } catch (error) {
    return next(new HttpError("Fetching comments failed", 500));
  }

  res.json({
    comments: houseWithComments.comments.map((comment) =>
      comment.toObject({ getters: true })
    ),
    message: "Get house successfully!"
  });
};

const editComment = async (req, res, next) => {

  const { content } = req.body;
  const commentId = req.params.cid;

  let comment;
  try{
    comment = await Comment.findById(commentId);
    if(isEmpty(comment)){
      return res.status(400).send("Could not find any comment with provided id!");
    }

    comment.content = content;
    const saveComment = await comment.save();
    if(isEmpty(saveComment)){
      return res.status(500).send("Could not save the comment!");
    }

  }catch(err){
    return res.status(500).send("Something went wrong!");
  }

  res.status(200).json({ comment: comment, message: "Update comment successfully!" });
}

const deleteComment = async (req, res, next) => {
  const commentId = req.params.cid;
  let comment;

  try{
    comment = await Comment.findById(commentId).populate("houseId");
    if(isEmpty(comment)){
      return res.status(404).send("Could not find the comment with provied id!");
    }

    const deleteComment = await comment.remove();
    if(isEmpty(deleteComment)){
      return res.status(500).send("Could not delete the comment!");
    }

    comment.houseId.comments.pull(comment);
    await comment.houseId.save();
  }catch(err){
    console.log(err);
    return res.status(500).send("Something went wrong!");
  }

  res.status(200).json({ comment: comment, message: "Delete comment successfully!" });
}

exports.createComment = createComment;
exports.getComment = getComment;
exports.getCommentsByHouseId = getCommentsByHouseId;
exports.editComment = editComment;
exports.deleteComment = deleteComment;
