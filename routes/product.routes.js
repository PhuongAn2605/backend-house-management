const express = require("express");
const { check } = require("express-validator");
const fileUpload = require("../middlewares/file-upload.js");

const productControllers = require("../controllers/product.controllers");

const router = express.Router();

router.get("/", productControllers.getProducts);
router.get("/user/:userName", productControllers.getProducts);

router.get("/:pid", productControllers.getProductById);

router.post(
  "/create/:userName",
  fileUpload.single("image"),
  [
    check("productName").not().isEmpty(),
    check("shortName").not().isEmpty(),
    check("expiration").not().isEmpty(),
    check("location").not().isEmpty(),
    check("description").not().isEmpty(),
    check("functions").not().isEmpty(),
    // check("image").not().isEmpty(),

    // check('houseId').not().isEmpty(),
  ],
  productControllers.createProduct
);

router.patch(
  "/edit/:pid",
  fileUpload.single("image"),
  [
    check("productName").not().isEmpty(),
    check("shortName").not().isEmpty(),
    check("expiration").not().isEmpty(),
    check("location").not().isEmpty(),
    check("description").not().isEmpty(),
    check("functions").not().isEmpty(),

    // check('houseId').not().isEmpty(),
  ],
  productControllers.editProduct
);

router.delete(
  "/delete/:pid",

  productControllers.deleteProduct
);

router.post(
  "/search-name/",
  // [check("productName").not().isEmpty()],
  productControllers.searchProductByName
);

router.post(
  "/search-location/",
  // [check("location").not().isEmpty()],
  productControllers.searchProductByLocation
);

module.exports = router;
