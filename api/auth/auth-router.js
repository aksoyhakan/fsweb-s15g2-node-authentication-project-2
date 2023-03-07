const router = require("express").Router();
const { usernameVarmi, rolAdiGecerlimi } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // bu secret'ı kullanın!
const UserModels = require("../users/users-model");
const jwt = require("jsonwebtoken");
const bycript = require("bcryptjs");

router.post("/register", rolAdiGecerlimi, (req, res, next) => {
  const hashPassword = bycript.hashSync(req.body.password, 8);
  req.body.password = hashPassword;
  UserModels.ekle(req.body)
    .then((response) => res.status(201).json(response))
    .catch((err) => next(err));
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status: 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});

router.post("/login", usernameVarmi, (req, res, next) => {
  UserModels.goreBul({ username: req.body.username }).then((response) => {
    response.forEach((item) => {
      if (bycript.compareSync(req.body.password, item.password)) {
        const token = generateToken(item);
        res
          .status(200)
          .json({ message: `${item.username} geri geldi`, token: token });
      } else {
        next({ status: 401, message: "Geçersiz kriter" });
      }
    });
  });
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status: 200
    {
      "message": "sue geri geldi!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    Token 1 gün sonra timeout olmalıdır ve aşağıdaki bilgiyi payloadında içermelidir:

    {
      "subject"  : 1       // giriş yapan kullanıcının user_id'si
      "username" : "bob"   // giriş yapan kullanıcının username'i
      "role_name": "admin" // giriş yapan kulanıcının role adı
    }
   */
});
function generateToken(user) {
  let payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  let option = {
    expiresIn: "1d",
  };
  return jwt.sign(payload, JWT_SECRET, option);
}

module.exports = router;
