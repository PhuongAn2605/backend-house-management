const express = require('express');

const houseLikeControllers = require('../controllers/houseLike.controllers');

const router = express.Router();

router.post('/:houseId', houseLikeControllers.houseLike);

module.exports = router;