const HttpError = require("../models/http-error");
const LoginHistory = require("../models/LoginHistory")

const getLastLogin = async (req, res, next) => {
    const { userId } = req.params;
    try{
        const lastLogin = await LoginHistory.find({ userId: userId }).sort({ "loginNo": -1 });

        return res.status(200).json({ lastLogin: lastLogin[1] });
    }catch(err){
        return next(new HttpError("Something went wrong", 500));
    }
};

exports.getLastLogin = getLastLogin;