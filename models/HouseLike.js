const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const houseLikeSchema = new Schema({
    houseId: {type: mongoose.Types.ObjectId, required: true, ref:'House'},
    userName: { type: String, required: true }
});

module.exports = mongoose.model('HouseLike', houseLikeSchema);