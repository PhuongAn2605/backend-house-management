const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const ExpireProductSchema = new Schema(
  {
    houseId: { type: mongoose.Types.ObjectId, required: true, ref: "House" },
    products: [{ type: mongoose.Types.ObjectId, ref: "Products" }],
  },
  { timestamps: true }
);

module.exports = mongoose.model("ExpireProduct", ExpireProductSchema);