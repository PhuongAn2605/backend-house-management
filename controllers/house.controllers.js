const { validationResult } = require('express-validator');
const isEmpty = require('is-empty');

const House = require('../models/House');
const HttpError = require('../models/http-error');
const Product = require('../models/Product');

const getHouses = async (req, res, next) => {
    
    let houses;
    try{
        houses = await House.find({});
        
        if(isEmpty(houses)){
            return next(new HttpError('NOt found any product', 404));
        }
    }catch(err){
        console.log(err);
        return next(new HttpError('Something went wrong', 500));
    }

    res.status(200).json({ houses });

}

const createHouse = async (req, res, next) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()){
        return next(new HttpError('Invalid data passed', 422));
    }

    const { userId } = req.body;

    let existingHouse;
    let newHouse;
    try{
        existingHouse = await House.find({ userId: userId });

        if(!isEmpty(existingHouse)){
            return next(new HttpError('House is owned by other user', 409));
        }

        newHouse = new House({
            userId,
            products: []
        });

        const saveHouse = await newHouse.save();

        if(isEmpty(saveHouse)){
            return next(new HttpError('Could not save the house', 500));
        }

    }catch(error){
        return next(new HttpError('Something went wrong', 500));
    }

    res.status(201).json({ userId: newHouse.userId, products: newHouse.products })
}

const getHouseById = async (req, res, next) => {
    const houseId = req.params.houseId;

    let house;
    let targetProducts = [];
    let targetComments = [];
    let houseLikes = [];

    try{
        house = await House.findById(houseId);

        const products = house.products;

        for(let pid of products){
            targetProducts.push(await Product.findById(pid));
        }

        const houseOfComments = await house.populate('comments');
        targetComments = houseOfComments.comments;

        const houseOfHouseLikes = await house.populate('houseLikes');
        houseLikes = houseOfHouseLikes.houseLikes;

    }catch(error){
        console.log(error);
        return next(new HttpError('Something went wrong', 500));
    }
    res.status(200).json({ house, targetProducts, targetComments, houseLikes });
}

exports.getHouses = getHouses;
exports.createHouse = createHouse;
exports.getHouseById = getHouseById;