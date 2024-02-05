const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const session = require("express-session");
const multer = require("multer");
const path = require('path');
const fs = require('fs');


mongoose.connect("mongodb://127.0.0.1:27017/vacayDB");

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: 'your-secret-key',  // Replace with a secure secret key
    resave: false,
    saveUninitialized: true,
}));

app.set("view engine", "ejs");
app.set("views", __dirname + "/views");
app.use(express.static(path.join(__dirname, 'public')));

const saltRounds = 10;

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage: storage });

const vacayGuestSchema = new mongoose.Schema({
    name: String,
    email: String,
    phoneNum: Number,
    password: String,
    type: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const vacayHostSchema = new mongoose.Schema({
    name: String,
    email: String,
    phoneNum: Number,
    password: String,
    bankNum: Number,
    type: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
});

const vacayAdminSchema = new mongoose.Schema({
    email: String,
    password: String,
});


const propertyHostSchema = new mongoose.Schema({
    name: String,
    address: String,
    description: String,
    price: String,
    guestNum: Number,
    hostId: { type: mongoose.Schema.Types.ObjectId, ref: 'VacayHost' },
    images: [
        {
            data: Buffer,
            contentType: String
        }
    ]
});

const bookingGuestSchema = new mongoose.Schema({
    name: String,
    phoneNum: Number,
    checkin: Date,
    checkout: Date,
    totalPrice: Number,
    bankNo: Number,
    bankType: String,
});

const bookingHistorySchema = new mongoose.Schema({
    propertyId: { type: mongoose.Schema.Types.ObjectId, ref: 'PropertyHost' },
    bookingId: { type: mongoose.Schema.Types.ObjectId, ref: 'BookingGuest' },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'VacayGuest' },
    timestamp: { type: Date, default: Date.now },
});


const VacayGuest = mongoose.model('VacayGuest', vacayGuestSchema);
const VacayHost = mongoose.model('VacayHost', vacayHostSchema);
const VacayAdmin = mongoose.model('VacayAdmin', vacayAdminSchema);
const PropertyHost = mongoose.model('PropertyHost', propertyHostSchema);
const BookingGuest = mongoose.model('BookingGuest', bookingGuestSchema);
const BookingHistory = mongoose.model('BookingHistory', bookingHistorySchema);

const Admin = new VacayAdmin({
    email: "vacayAdmin@gmail.com",
    password: "753951Admin",
});
Admin.save();

app.get("/", function (req, res) {
    res.render("welcome");
});

app.get("/welcome", function (req, res) {
    res.render("loginPage");
});

app.get("/register", function (req, res) {
    res.render("signupMain");
});

app.get("/guestsignup", function (req, res) {
    res.render("signupPage");
});

app.get("/hostsignup", function (req, res) {
    res.render("signupHost");
});

app.get("/loginAdmin", function (req, res) {
    res.render("logAdmin");
});

app.post('/mainAdmin', async function (req, res) {
    const { email, password } = req.body;

    try {
        console.log('Attempting login with:', email, password);

        // Check if the admin credentials are valid
        const admin = await VacayAdmin.findOne({ email, password }).exec();

        console.log('Found admin:', admin);

        if (admin) {
            // Successful login, you can redirect to a dashboard or render another page
            res.render('adminMain');
        } else {
            // Invalid credentials, render login page with an error message
            res.render('logAdmin', { error: 'Invalid credentials' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});



app.post("/login", async function (req, res) {
    const emailUse = req.body.email;
    const passwordUse = req.body.password;

    try {
        let user, userRole;

        // Check if user is a guest
        const foundVacayGuest = await VacayGuest.findOne({ email: emailUse });

        if (foundVacayGuest) {
            user = foundVacayGuest;
            userRole = "guest";
        } else {
            // Check if user is a host
            const foundVacayHost = await VacayHost.findOne({ email: emailUse });

            if (foundVacayHost) {
                user = foundVacayHost;
                userRole = "host";
            }
        }

        if (user) {
            const passwordMatch = await bcrypt.compare(passwordUse, user.password);

            if (passwordMatch) {
                // Set session for the user
                req.session.user = {
                    id: user._id,
                    type: userRole,
                };

                console.log("Session after login:", req.session.user); // Log the session

                if (userRole === "guest") {
                    res.redirect("/mainView");
                } else {
                    res.redirect("/mainHost");
                }
            } else {
                res.redirect("/login");
            }
        } else {
            res.redirect("/login");
        }
    } catch (err) {
        console.error(err);
        res.redirect("/login");
    }
});



app.post("/guestSign", async function (req, res) {
    try {
        const hash = await bcrypt.hash(req.body.password, saltRounds);

        const newGuest = new VacayGuest({
            name: req.body.guestName,
            email: req.body.email,
            phoneNum: req.body.phoneNum,
            password: hash,
            type: "Guest",
            userId: (req.session.user && req.session.user.id) || null
        });

        await newGuest.save();
        res.redirect("/mainView");
    } catch (err) {
        console.log(err);
        res.redirect("/login");
    }
});

app.post("/hostSign", async function (req, res) {
    try {
        const hash = await bcrypt.hash(req.body.password, saltRounds);

        const newHost = new VacayHost({
            name: req.body.hostName,
            email: req.body.email,
            phoneNum: req.body.phoneNum,
            bankNum: req.body.bankNum,
            password: hash,
            type: "Host",
            userId: (req.session.user && req.session.user.id) || null
        });

        await newHost.save();
        res.redirect("/mainHost");
    } catch (err) {
        console.log(err);
        res.redirect("/login");
    }
});

app.get("/mainView", async function (req, res) {
    try {
        const propertyHosts = await PropertyHost.find();
        res.render("mainView", { propertyHosts, user: req.session.user });
    } catch (err) {
        console.log(err);
        res.redirect("/login");
    }
});

app.get("/mainHost", function (req, res) {
    res.render("mainHost");
});

app.get("/settings", function (req, res) {
    res.render("setting");
});
app.get("/settingsGuest", function (req, res) {
    res.render("settingGuest");
});

app.get("/settingsAdmin", function (req, res) {
    res.render("adminSetting");
});

app.get("/profileGuest", async function (req, res) {
    try {
        // Assuming user details are available in req.session.user
        const user = req.session.user;

        if (user && user.type === "guest") {
            // Assuming you have a VacayGuest model
            const vacayGuest = await VacayGuest.findOne({ _id: user.id });

            if (vacayGuest) {
                res.render("profilePage.ejs", {
                    profileName: vacayGuest.name,
                    profileEmail: vacayGuest.email,
                    profilePhoneNumber: vacayGuest.phoneNum,
                    profileStatus: vacayGuest.type,
                    // Add other details as needed
                });
            } else {
                // Handle the case when VacayGuest details are not found
                console.log("VacayGuest details not found");
                res.status(404).send("VacayGuest details not found");
            }
        } else {
            // Handle the case when the user doesn't have the required role
            console.log("User doesn't have the required role");
            res.redirect("/login"); // Redirect to login page or handle appropriately
        }
    } catch (error) {
        console.error("Error fetching profile details:", error);
        res.status(500).send("Internal Server Error");
    }
});



app.get("/profile", async function (req, res) {
    try {
        // Assuming user details are available in req.session.user
        const user = req.session.user;

        console.log(req.query); // Use req.query to access query parameters

        if (user && user.type === "host") {
            // Assuming you have a VacayHost model
            const vacayHost = await VacayHost.findOne({ _id: user.id });

            if (vacayHost) {
                res.render("profileHost.ejs", {
                    profileName: vacayHost.name,
                    profileEmail: vacayHost.email,
                    profilePhoneNumber: vacayHost.phoneNum,
                    profileStatus: vacayHost.type,
                    // Add other details as needed
                });
            } else {
                // Handle the case when VacayHost details are not found
                console.log("VacayHost details not found");
                res.status(404).send("VacayHost details not found");
            }
        } else {
            // Handle the case when the user doesn't have the required role
            console.log("User doesn't have the required role");
            res.redirect("/login"); // Redirect to login page or handle appropriately
        }
    } catch (error) {
        console.error("Error fetching profile details:", error);
        res.status(500).send("Internal Server Error");
    }
});



app.get("/bookHistory", async function (req, res) {
    try {
        const user = req.session.user;

        if (user && user.type === "guest") {
            // Fetch booking history for the current guest user
            const bookingHistory = await BookingHistory.find({ userId: user.id })
                .populate("propertyId")
                .populate("bookingId");

            res.render("bookingHistory", { bookingHistory });
        } else {
            // Handle the case when the user doesn't have the required role
            console.log("User doesn't have the required role");
            res.redirect("/login"); // Redirect to login page or handle appropriately
        }
    } catch (error) {
        console.error("Error fetching booking history:", error);
        res.status(500).send("Internal Server Error");
    }
});



app.get("/propertyform", function (req, res) {
    res.render("addProp");
});

app.post("/proplist", upload.array('images', 5), async function (req, res) {
    try {
        const newProperty = new PropertyHost({
            name: req.body.propName,
            address: req.body.propAddrs,
            description: req.body.propDesc,
            price: req.body.propPrice,
            guestNum: req.body.propGuest,
            hostId: req.session.user ? req.session.user.id : null,
            images: req.files.map(file => ({
                data: fs.readFileSync(file.path),
                contentType: file.mimetype
            })),
        });

        await newProperty.save();
        res.redirect("/propertylist");
    } catch (err) {
        console.log(err);
        res.redirect("/propertylist");
    }
});

app.get("/propertylist", async function (req, res) {
    try {
        const propertyHosts = await PropertyHost.find();
        res.render("propertyList", { propertyHosts, user: req.session.user });
    } catch (err) {
        console.log(err);
        res.render("propertyList", { propertyHosts: [], user: req.session.user });
    }
});

app.post("/removeproperty", async function (req, res) {
    const propertyIdToRemove = req.body.propertyId;

    try {
        const removedProperty = await PropertyHost.findByIdAndDelete(propertyIdToRemove);

        if (removedProperty) {
            console.log("Property removed:", removedProperty);

            const hostId = removedProperty.hostId;
            console.log("Host ID:", hostId);

            const host = await VacayHost.findByIdAndUpdate(
                hostId,
                { $pull: { properties: propertyIdToRemove } },
                { new: true }
            );

            if (host) {
                console.log("Property removed from host:", host);
            } else {
                console.log("Host not found");
            }

            res.redirect("/propertylist");
        } else {
            res.status(404).send("Property not found");
        }
    } catch (err) {
        console.error("Error removing property:", err);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/propertyView/:propertyId", async function (req, res) {
    try {
        const propertyId = req.params.propertyId;
        const property = await PropertyHost.findById(propertyId);

        if (property) {
            res.render("viewProperty", { property: property });
        } else {
            res.status(404).send("Property not found");
        }
    } catch (err) {
        console.error("Error fetching property details:", err);
        res.status(500).send("Internal Server Error");
    }
});

app.post("/bookingProp/:propertyId", async function(req, res) {
    try {
        const propertyId = req.params.propertyId;
        const property = await PropertyHost.findById(propertyId);

        if (property) {
            // Assuming you have a BookingGuest model
            const newBooking = new BookingGuest({
                name: req.session.user.name, // Assuming you store user's name in the session
                phoneNum: req.session.user.phoneNum, // Assuming you store user's phone number in the session
                checkin: req.body.checkIn,
                checkout: req.body.checkOut,
                totalPrice: calculateTotalPrice(req.body.checkIn, req.body.checkOut, property.price),
                bankNo: req.body.bankNo, // Assuming you have a form field for bank number
                bankType: req.body.bankType, // Assuming you have a form field for bank type
            });

            // Save the booking to the database
            await newBooking.save();

            res.render("paymentGateway", { property, booking: newBooking });
        } else {
            res.status(404).send("Property not found");
        }
    } catch (err) {
        console.error("Error processing booking:", err);
        res.status(500).send("Internal Server Error");
    }
});


function calculateTotalPrice(checkIn, checkOut, price) {
    const checkInDate = new Date(checkIn);
    const checkOutDate = new Date(checkOut);

    // Calculate the number of nights between check-in and check-out
    const timeDifference = checkOutDate.getTime() - checkInDate.getTime();
    const numberOfNights = Math.ceil(timeDifference / (1000 * 3600 * 24));

    // Multiply the number of nights by the nightly rate (property price)
    const totalPrice = numberOfNights * price;

    return totalPrice;
}


app.post("/paymentConfirmation", async function(req, res) {
    try {
        // Fetch the property and booking details from the database
        const propertyId = req.body.propertyId;
        const bookingId = req.body.bookingId;

        // This is just an example, replace it with your actual database queries
        const property = await PropertyHost.findById(propertyId);
        const booking = await BookingGuest.findById(bookingId);

        // Check if property and booking are found
        if (!property || !booking) {
            return res.status(404).send("Property or booking not found");
        }

        // Create a new BookingHistory entry
        const newBookingHistory = new BookingHistory({
            propertyId: property._id,
            bookingId: booking._id,
            userId: req.session.user.id,
        });

        // Save the booking details into the BookingHistory database
        await newBookingHistory.save();

        // Render the bookingList.ejs template with the property and booking details
        res.render("bookingList", { property, booking, bookingHistory: [newBookingHistory] });
    } catch (err) {
        console.error("Error fetching property and booking details:", err);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/propVerify", async function (req, res) {
    try {
        // Fetch all PropertyHost data from every VacayHost
        const allPropertyHosts = await PropertyHost.find().populate('hostId');
        
        // Render the propVerifyList.ejs template with the fetched data
        res.render("propVerifyList", { propertyHosts: allPropertyHosts });
    } catch (error) {
        console.error("Error fetching PropertyHost data:", error);
        res.status(500).send("Internal Server Error");
    }
});


app.get("/logoutAdmin", function (req, res) {
    res.render("welcome");
});

app.get("/guestView", function (req, res) {
    res.redirect("/mainView");
});

app.get("/logout", function (req, res) {
    req.session.destroy(function (err) {
        if (err) {
            console.log(err);
        } else {
            res.redirect("/welcome");
        }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
