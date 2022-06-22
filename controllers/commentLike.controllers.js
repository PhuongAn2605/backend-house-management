const isEmpty = require("is-empty");
const Comment = require("../models/Comment");
const CommentLike = require("../models/CommentLike");
const HttpError = require("../models/http-error");

const likeReact = async (req, res, next) => {
  const { like, userName } = req.body;

  const commentId = req.params.commentId;

  let saveLikeComment;
  let comment = await Comment.findById(commentId);
  let targetCommentLikes;

  if (like) {
    const commentLike = new CommentLike({
      commentId,
      userName,
    });

    try {
      saveLikeComment = await commentLike.save();
      if (isEmpty(saveLikeComment)) {
        return next(new HttpError("Could not save the like", 500));
      }

      comment.commentLikes.push(saveLikeComment);
      await comment.save();
    } catch (err) {
      console.log(err);
      return next(new HttpError("Something went wrong!", 500));
    }
  } else {
    const like = await CommentLike.findOne({
      commentId: commentId,
      userName: userName,
    }).populate("commentId");
    if (isEmpty(like)) {
      return next(
        new HttpError("Could not find any like for the comment", 404)
      );
    }
    const deleteLike = await like.remove();
    if (isEmpty(deleteLike)) {
      return next(new HttpError("Could not delete the like", 500));
    }
    like.commentId.commentLikes.pull(like);
    await like.commentId.save();
  }
  const commentOfCommentLikes = await comment.populate("commentLikes");
  targetCommentLikes = commentOfCommentLikes.commentLikes;

  res.status(201).json({ commentLikes: targetCommentLikes });
};

exports.likeReact = likeReact;
