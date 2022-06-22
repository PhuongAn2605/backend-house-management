const express = require("express");
const { check } = require("express-validator");

const userControllers = require("../controllers/house.controllers");
const houseControllers = require('../controllers/house.controllers');

const router = express.Router();

router.get('/', houseControllers.getHouses);

router.get('/:houseId', houseControllers.getHouseById);

router.post('/create', houseControllers.createHouse);

module.exports = router;

