require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");

const app = express();
app.use(express.json());
app.use(cors());

// ✅ Connect to MongoDB Atlas
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log("MongoDB Error:", err));

// ✅ Define Mongoose Schemas
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
});
const User = mongoose.model("User", UserSchema);

const TransactionSchema = new mongoose.Schema({
  date: String,
  category: String,
  description: String,
  amount: Number,
  type: { type: String, enum: ["Income", "Expense"], required: true },
  reference: String,
});
const Transaction = mongoose.model("Transaction", TransactionSchema);

const InvoiceSchema = new mongoose.Schema({
  invoiceNumber: { type: String, required: true, unique: true },
  date: { type: String, required: true },
  client: { type: String, required: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ["Paid", "Pending"], required: true },
  file: String,
});
const Invoice = mongoose.model("Invoice", InvoiceSchema);

// ✅ Multer Setup for File Uploads
const storage = multer.diskStorage({
  destination: "./uploads/",
  filename: (req, file, cb) => {
    cb(null, file.fieldname + "-" + Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

// ✅ Middleware for Authentication
const authMiddleware = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid token" });
  }
};

// ✅ User Registration
app.post(
  "/register",
  [
    body("name").notEmpty().withMessage("Name is required"),
    body("email").isEmail().withMessage("Valid email required"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });

    if (existingUser) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    res.json({ message: "User registered successfully" });
  }
);

// ✅ User Login
app.post(
  "/login",
  [
    body("email").isEmail().withMessage("Valid email required"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
  }
);

// ✅ Get User Details (Protected)
app.get("/user", authMiddleware, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json(user);
});

// ✅ CRUD for Transactions
app.post("/transactions", authMiddleware, async (req, res) => {
  try {
    const transaction = new Transaction(req.body);
    await transaction.save();
    res.json(transaction);
  } catch (error) {
    res.status(400).json({ message: "Error creating transaction", error: error.message });
  }
});

app.get("/transactions", authMiddleware, async (req, res) => {
  try {
    const transactions = await Transaction.find();
    res.json(transactions);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// ✅ Full CRUD for Invoices

// CREATE an Invoice
app.post("/invoices", authMiddleware, async (req, res) => {
  try {
    const invoice = new Invoice(req.body);
    await invoice.save();
    res.json({ message: "Invoice created successfully", invoice });
  } catch (error) {
    res.status(400).json({ message: "Error creating invoice", error: error.message });
  }
});

// READ all Invoices
app.get("/invoices", authMiddleware, async (req, res) => {
  try {
    const invoices = await Invoice.find();
    res.json(invoices);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// READ a single Invoice by ID
app.get("/invoices/:id", authMiddleware, async (req, res) => {
  try {
    const invoice = await Invoice.findById(req.params.id);
    if (!invoice) return res.status(404).json({ message: "Invoice not found" });
    res.json(invoice);
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// UPDATE an Invoice
app.put("/invoices/:id", authMiddleware, async (req, res) => {
  try {
    const updatedInvoice = await Invoice.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!updatedInvoice) return res.status(404).json({ message: "Invoice not found" });
    res.json({ message: "Invoice updated successfully", updatedInvoice });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// DELETE an Invoice
app.delete("/invoices/:id", authMiddleware, async (req, res) => {
  try {
    const deletedInvoice = await Invoice.findByIdAndDelete(req.params.id);
    if (!deletedInvoice) return res.status(404).json({ message: "Invoice not found" });
    res.json({ message: "Invoice deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// ✅ Upload Invoice File
app.post("/upload-invoice", authMiddleware, upload.single("file"), (req, res) => {
  res.json({ filePath: `/uploads/${req.file.filename}` });
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
