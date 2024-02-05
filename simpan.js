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
            bcrypt.compare(passwordUse, user.password, function (err, result) {
                if (result === true) {
                    // Set session for the user
                    req.session.user = {
                        id: user._id,
                        type: userRole,
                    };

                    if (userRole === "guest") {
                        res.redirect("/mainView");
                    } else {
                        res.redirect("/mainHost");
                    }
                } else {
                    res.redirect("/login");
                }
            });
        } else {
            res.redirect("/login");
        }
    } catch (err) {
        console.log(err);
        res.redirect("/login");
    }
});