const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const LoginHistorySchema = new Schema({
  userId: {
    type: mongoose.Types.ObjectId,
    ref: "User",
  },
  loginAt: {
    type: Date,
    default: Date.now(),
  },
  loginNo: {
    type: Number,
    default: 1,
  },
});

module.exports = mongoose.model("LoginHistory", LoginHistorySchema);