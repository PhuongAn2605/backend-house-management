const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const productSchema = new Schema(
  {
    productName: { type: String, required: true },
    shortName: { type: String, required: true },
    image: { type: String, required: true },
    expiration: { type: Date, required: true },
    functions: { type: String, required: true },
    location: { type: String, required: true },
    description: { type: String, required: true },
    commentId: {
      type: mongoose.Types.ObjectId,
      ref: "Comment",
    },
    houseId: { type: mongoose.Types.ObjectId, ref: "House" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Product", productSchema);
