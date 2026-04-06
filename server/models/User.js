const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema({
  // Authentication
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
    lowercase: true,
    match: [/.+\@.+\..+/, "Please provide a valid email address"],
    index: true
  },
  password: {
    type: String,
    required: [true, "Password is required"],
    minlength: [8, "Password must be at least 8 characters"],
    select: false // Don't return password by default
  },

  // Wallet
  walletBalance: {
    type: Number,
    default: 0,
    min: [0, "Balance cannot be negative"]
  },

  // OTP
  otp: {
    type: String,
    default: null
  },
  otpExpires: {
    type: Date,
    default: null
  },

  // PIN
  transactionPin: {
    type: String,
    default: null,
    select: false // Don't return PIN by default
  },
  pinAttempts: {
    type: Number,
    default: 0
  },
  pinLockedUntil: {
    type: Date,
    default: null
  },

  // Personal Information
  fullName: {
    type: String,
    default: null,
    match: [/^[a-zA-Z\s]+$/, "Full name can only contain letters and spaces"]
  },
  phone: {
    type: String,
    default: null,
    match: [/^\+?[0-9]{10,}$/, "Please provide a valid phone number"]
  },
  dob: {
    type: Date,
    default: null,
    validate: {
      validator: function(value) {
        if (!value) return true;
        const age = new Date().getFullYear() - value.getFullYear();
        return age >= 18 && age <= 120;
      },
      message: "You must be at least 18 years old"
    }
  },

  // KYC (Know Your Customer)
  bvn: {
    type: String,
    default: null,
    sparse: true // Allow multiple null values
  },
  nin: {
    type: String,
    default: null,
    sparse: true
  },
  kycLevel: {
    type: Number,
    enum: [1, 2, 3],
    default: 1
  },
  kycVerified: {
    type: Boolean,
    default: false
  },
  kycCompletedAt: {
    type: Date,
    default: null
  },
  kycDocuments: [{
    type: {
      type: String,
      enum: ["bvn", "nin", "passport", "drivers_license"]
    },
    url: String,
    uploadedAt: {
      type: Date,
      default: Date.now
    }
  }],

  // Account Status
  accountStatus: {
    type: String,
    enum: ["active", "suspended", "locked", "closed"],
    default: "active"
  },
  lastLogin: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockedUntil: {
    type: Date,
    default: null
  },

  // Two-Factor Authentication
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  twoFactorSecret: {
    type: String,
    default: null,
    select: false
  },

  // Metadata
  deviceTokens: [String],
  referralCode: String,
  referredBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null
  }

}, { 
  timestamps: true // Automatically add createdAt and updatedAt
});

// Pre-save middleware to hash password
userSchema.pre("save", async function(next) {
  // Only hash if password is modified or new
  if (!this.isModified("password")) return next();

  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Method to hash PIN
userSchema.methods.hashPin = async function(pin) {
  return await bcrypt.hash(pin, 10);
};

// Method to compare PIN
userSchema.methods.comparePin = async function(enteredPin) {
  return await bcrypt.compare(enteredPin, this.transactionPin);
};

// Method to check if account is locked
userSchema.methods.isAccountLocked = function() {
  return this.lockedUntil && this.lockedUntil > new Date();
};

// Method to check if PIN is locked
userSchema.methods.isPinLocked = function() {
  return this.pinLockedUntil && this.pinLockedUntil > new Date();
};

// Method to increment login attempts
userSchema.methods.incLoginAttempts = async function() {
  // Reset attempts if lock has expired
  if (this.lockedUntil && this.lockedUntil < new Date()) {
    return await this.updateOne({
      $set: { loginAttempts: 1, lockedUntil: null }
    });
  }

  // Increment attempts
  const updates = { $inc: { loginAttempts: 1 } };

  // Lock account if too many attempts
  const maxAttempts = 5;
  if (this.loginAttempts + 1 >= maxAttempts && !this.isAccountLocked()) {
    updates.lockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
  }

  return await this.updateOne(updates);
};

// Method to reset login attempts
userSchema.methods.resetLoginAttempts = async function() {
  return await this.updateOne({
    $set: { loginAttempts: 0, lockedUntil: null }
  });
};

// Method to get public user data (exclude sensitive fields)
userSchema.methods.toJSON = function() {
  const obj = this.toObject();
  delete obj.password;
  delete obj.transactionPin;
  delete obj.twoFactorSecret;
  delete obj.otp;
  return obj;
};

// Create indexes for performance
userSchema.index({ email: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ accountStatus: 1 });
userSchema.index({ kycVerified: 1 });

module.exports = mongoose.model("User", userSchema);