const isEmpty = require("is-empty");
const House = require("../models/House");
const HouseLike = require("../models/HouseLike");
const HttpError = require("../models/http-error");

const houseLike = async (req, res, next) => {
  const { like, userName } = req.body;
  const houseId = req.params.houseId;

  let saveHouseLike;
  let house;
  let targetHouseLikes;

  house = await House.findById(houseId);

  if (like) {
    const houseLike = new HouseLike({
      houseId,
      userName,
    });

    try {
      saveHouseLike = await houseLike.save();
      if (isEmpty(saveHouseLike)) {
        return next(new HttpError("Could not save the like", 500));
      }

      house.houseLikes.push(saveHouseLike);
      await house.save();

      // const houseOfHouseLikes = await house.populate('houseLikes');
      // targetHouseLikes = houseOfHouseLikes.houseLikes;
    } catch (error) {
      console.log(error);
      return next(new HttpError("Something went wrong", 500));
    }
  } else {
    const like = await HouseLike.findOne({
      houseId: houseId,
      userName: userName,
    }).populate("houseId");

    if (!isEmpty(like)) {
      const deleteLike = await like.remove();

      if (isEmpty(deleteLike)) {
        return next(new HttpError("Could not delete the like", 500));
      }

      like.houseId.houseLikes.pull(like);
      await like.houseId.save();
    }

  }
  const houseOfHouseLikes = await house.populate("houseLikes");
  targetHouseLikes = houseOfHouseLikes.houseLikes;

  res.status(201).send({ houseLikes: targetHouseLikes });
};

module.exports.houseLike = houseLike;
