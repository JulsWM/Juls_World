const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const crypto = require("crypto-nodejs");

const UserShema = new Schema({
  email: { type: String, unique: true, lowercase: true },
  hash: String,
  salt: String
});

UserShema.pre("save", function(next) {
  const user = this;

  user.salt = crypto.randomBytes(16).toString("hex");
   user.hash = crypto
      .pbkdf2Sync(user.password, user.salt, 10000, 512, "sha512")
      .toString("hex");
    next();
   });


UserSchema.methods.comparePassword = function(canidatePassword, callback) {
    var candidateHash = crypto
      .pbkdf2Sync(candidatePassword, this.salt, 10000, 512, "sha512")
        .toString("hex");
      if (!candidateHash) {
        const err = new Error("Failed Hash");
        callback(err, false);
      } else if (this.hash === candidateHash) {
        callback(null, true);
      } else {
        callback(null, false);
      }
   

const User = mongoose.model("User", UserSchema);
module.exports = User;
