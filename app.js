const express = require('express');
const mongoose = require('mongoose');
const HttpError = require('./models/http-error');
const path = require("path");
const fs = require("fs");

const userRouter = require('./routes/user.routes');
const houseRouter = require('./routes/house.routes');
const productRouter = require('./routes/product.routes');
const commentRouter = require('./routes/comment.routes');
const commentLikeRouter = require('./routes/commentLike.routes');
const replyRouter = require('./routes/reply.routes');
const houseLikeRouter = require('./routes/houseLike.routes');
const notificationRouter = require('./routes/notification.routes');


const bodyParser = require('body-parser');


// const dotenv = require("dotenv")
// dotenv.config()

const app = express();
app.use(bodyParser.json());

app.use("/uploads/images", express.static(path.join("uploads", "images")));


app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept, Authorization"
    );
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE");
  
    next();
  });


app.use('/api/user', userRouter);
app.use('/api/product', productRouter);
app.use('/api/comment', commentRouter);
app.use('/api/comment-like', commentLikeRouter);
app.use('/api/reply', replyRouter);
app.use('/api/house', houseRouter);
app.use('/api/house-like', houseLikeRouter);
app.use('/api/notification', notificationRouter);

app.use((req, res, next) => {
    const error = new HttpError('Could not find the route', 404);
    throw error;
});

app.use((error, req, res, next) => {
  if (req.file) {
    fs.unlink(req.file.path, (err) => {
      console.log(err);
    });
  }
  if (res.headerSent) {
    return next(error);
  }
  res.status(error.code || 500);
  res.json({ message: error.message || "An unknown error occurred!" });
});

app.use((error, req, res, next) => {
  if(req.file){
    fs.unlink(req.file.path, err => {
      console.log(err);
    });
  }
  if(res.headerSent){
    return next(error);
  }
  res.status(error.code || 500);
  res.json({ message: error.message || "An unknown error occurred!"});
})
  

const MONGO_URL = `mongodb://localhost:27017/product-management`;
mongoose.connect(MONGO_URL).then(() => {
    app.listen(process.env.PORT || 5000);
}).then(() => {
    console.log('Connected to db!')
}).catch(err => {
    console.log(err);
});
