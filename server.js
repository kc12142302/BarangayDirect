const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { promisify } = require("util");
const mysql = require("mysql2");
const multer = require("multer");
const session = require("express-session");

const app = express();
const scrypt = promisify(crypto.scrypt);
const rejectionReasons = [
    "False information",
    "Duplicate report",
    "Not a barangay concern",
    "Insufficient details",
    "Other"
];
const requiredResidentAddress = "Cogon East, Carmen, Cebu";
const residentSecurityQuestions = ["color", "number", "food"];
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: "barangay-direct-secret",
    resave: false,
    saveUninitialized: false
}));

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "barangay_direct"
});

db.on("error", (err) => {
    console.log("MySQL connection error:", err.message);
});

// File upload settings
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, "uploads/");
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + "-" + file.originalname);
    }
});

const upload = multer({ storage: storage });

const incidentStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, "uploads/");
    },
    filename: function (req, file, cb) {
        const extension = path.extname(file.originalname).toLowerCase();
        cb(null, `incident-${Date.now()}-${crypto.randomBytes(6).toString("hex")}${extension}`);
    }
});

const incidentUpload = multer({
    storage: incidentStorage,
    limits: { fileSize: 50 * 1024 * 1024 },
    fileFilter: function (req, file, cb) {
        if (file.mimetype.startsWith("image/") || file.mimetype.startsWith("video/")) {
            return cb(null, true);
        }

        cb(new Error("Only image or video files are allowed."));
    }
});

function requireOfficial(req, res, next) {
    if (!req.session.official_id) {
        return res.status(401).json({ error: "Official login required" });
    }

    next();
}

function requireResident(req, res, next) {
    if (!req.session.resident_id) {
        return res.redirect("/resident-login.html");
    }

    db.query(
        "SELECT is_blocked FROM resident_accounts WHERE resident_id = ?",
        [req.session.resident_id],
        (err, results) => {
            if (err) {
                console.log("Resident access check error:", err.message);
                return res.status(500).send("There was an error checking your account.");
            }

            if (results.length === 0 || results[0].is_blocked) {
                return req.session.destroy(() => {
                    res.clearCookie("connect.sid");
                    res.redirect("/resident-login.html?error=blocked");
                });
            }

            next();
        }
    );
}

async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");
    const derivedKey = await scrypt(password, salt, 64);
    return `${salt}:${derivedKey.toString("hex")}`;
}

async function verifyPassword(password, storedPassword) {
    const [salt, storedHash] = String(storedPassword || "").split(":");

    if (!salt || !storedHash || !/^[a-f0-9]+$/i.test(storedHash)) {
        return false;
    }

    const derivedKey = await scrypt(password, salt, 64);
    const storedKey = Buffer.from(storedHash, "hex");

    return storedKey.length === derivedKey.length &&
        crypto.timingSafeEqual(storedKey, derivedKey);
}

function recordIncidentTransaction(incidentId, residentId, officialId, status, callback) {
    db.query(
        `INSERT INTO transactional_record
            (incident_id, resident_id, official_id, verification_id, \`date\`, \`time\`, status)
         SELECT ?, ra.resident_id, ?, ra.verification_id, CURDATE(), CURTIME(), ?
         FROM resident_accounts ra
         WHERE ra.resident_id = ?`,
        [incidentId, officialId, status, residentId],
        (err, result) => {
            if (!err && result.affectedRows === 0) {
                return callback(new Error("Resident account was not found for the transaction record."));
            }

            callback(err, result);
        }
    );
}

// Connect to MySQL
db.connect((err) => {
    if (err) {
        console.log("Database connection failed:", err.message);
    } else {
        console.log("Database connected successfully!");
        db.query(`
            CREATE TABLE IF NOT EXISTS resident_accounts (
                resident_id INT NOT NULL AUTO_INCREMENT,
                verification_id INT NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                age INT NOT NULL,
                gender VARCHAR(20) NOT NULL,
                address VARCHAR(255) NOT NULL,
                purok VARCHAR(50) NOT NULL,
                mobile_number VARCHAR(20) NOT NULL,
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(200) NOT NULL,
                security_question VARCHAR(20) DEFAULT NULL,
                security_answer_hash VARCHAR(200) DEFAULT NULL,
                is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (resident_id),
                UNIQUE KEY unique_verification_account (verification_id),
                CONSTRAINT fk_resident_verification
                    FOREIGN KEY (verification_id)
                    REFERENCES resident_verification (verification_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        `, (tableError) => {
            if (tableError) {
                console.log("Resident account table setup failed:", tableError.message);
                return;
            }

            db.query(
                "ALTER TABLE resident_accounts ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN NOT NULL DEFAULT FALSE",
                (blockedColumnError) => {
                    if (blockedColumnError) {
                        console.log("Resident account status setup failed:", blockedColumnError.message);
                    }
                }
            );

            db.query(
                "ALTER TABLE resident_accounts ADD COLUMN IF NOT EXISTS security_question VARCHAR(20) DEFAULT NULL",
                (questionColumnError) => {
                    if (questionColumnError) {
                        console.log("Resident security question setup failed:", questionColumnError.message);
                    }
                }
            );

            db.query(
                "ALTER TABLE resident_accounts ADD COLUMN IF NOT EXISTS security_answer_hash VARCHAR(200) DEFAULT NULL",
                (answerColumnError) => {
                    if (answerColumnError) {
                        console.log("Resident security answer setup failed:", answerColumnError.message);
                    }
                }
            );

            db.query(`
                CREATE TABLE IF NOT EXISTS incident_reports (
                    incident_id INT NOT NULL AUTO_INCREMENT,
                    resident_id INT NOT NULL,
                    description TEXT NOT NULL,
                    location VARCHAR(255) NOT NULL,
                    media_filename VARCHAR(255) DEFAULT NULL,
                    media_type VARCHAR(100) DEFAULT NULL,
                    rejection_reason VARCHAR(255) DEFAULT NULL,
                    status ENUM('Pending','Processing','Resolved','Rejected') NOT NULL DEFAULT 'Pending',
                    submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (incident_id),
                    CONSTRAINT fk_incident_resident
                        FOREIGN KEY (resident_id)
                        REFERENCES resident_accounts (resident_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            `, (incidentError) => {
                if (incidentError) {
                    console.log("Incident report table setup failed:", incidentError.message);
                    return;
                }

                db.query(
                    "ALTER TABLE incident_reports MODIFY COLUMN status ENUM('Pending','Processing','Resolved','Rejected') NOT NULL DEFAULT 'Pending'",
                    (statusError) => {
                        if (statusError) {
                            console.log("Incident status setup failed:", statusError.message);
                        }
                    }
                );

                db.query(
                    "ALTER TABLE incident_reports ADD COLUMN IF NOT EXISTS rejection_reason VARCHAR(255) DEFAULT NULL",
                    (reasonColumnError) => {
                        if (reasonColumnError) {
                            console.log("Incident rejection reason setup failed:", reasonColumnError.message);
                        }
                    }
                );

                db.query(`
                    CREATE TABLE IF NOT EXISTS transactional_record (
                        transaction_id INT NOT NULL AUTO_INCREMENT,
                        incident_id INT NOT NULL,
                        resident_id INT NOT NULL,
                        official_id INT DEFAULT NULL,
                        verification_id INT NOT NULL,
                        \`date\` DATE NOT NULL,
                        \`time\` TIME NOT NULL,
                        status ENUM('Pending','Processing','Resolved','Rejected') NOT NULL,
                        PRIMARY KEY (transaction_id),
                        KEY idx_transaction_incident (incident_id),
                        KEY idx_transaction_resident (resident_id),
                        KEY idx_transaction_official (official_id),
                        KEY idx_transaction_verification (verification_id),
                        CONSTRAINT fk_transaction_incident
                            FOREIGN KEY (incident_id) REFERENCES incident_reports (incident_id),
                        CONSTRAINT fk_transaction_resident
                            FOREIGN KEY (resident_id) REFERENCES resident_accounts (resident_id),
                        CONSTRAINT fk_transaction_official
                            FOREIGN KEY (official_id) REFERENCES officials (official_id),
                        CONSTRAINT fk_transaction_verification
                            FOREIGN KEY (verification_id) REFERENCES resident_verification (verification_id)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                `, (transactionTableError) => {
                    if (transactionTableError) {
                        console.log("Transaction record table setup failed:", transactionTableError.message);
                    }
                });

                db.query(`
                    CREATE TABLE IF NOT EXISTS resident_password_resets (
                        reset_id INT NOT NULL AUTO_INCREMENT,
                        resident_id INT NOT NULL,
                        token_hash CHAR(64) NOT NULL UNIQUE,
                        expires_at DATETIME NOT NULL,
                        used_at DATETIME DEFAULT NULL,
                        PRIMARY KEY (reset_id),
                        CONSTRAINT fk_password_reset_resident
                            FOREIGN KEY (resident_id)
                            REFERENCES resident_accounts (resident_id)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                `, (resetError) => {
                    if (resetError) {
                        console.log("Password reset table setup failed:", resetError.message);
                    }
                });
            });
        });
    }
});

app.get("/official.html", (req, res) => {

    if (!req.session.official_id) {
        return res.redirect("/official-login.html");
    }

    res.sendFile(path.join(__dirname, "public", "official.html"));
});

app.get("/resident.html", requireResident, (req, res) => {
    res.sendFile(path.join(__dirname, "public", "resident.html"));
});

app.get("/verification-document/:filename", requireOfficial, (req, res) => {
    const { filename } = req.params;

    if (!/^[a-zA-Z0-9._-]+$/.test(filename)) {
        return res.status(400).send("Invalid document filename.");
    }

    const uploadsDirectory = path.resolve(__dirname, "uploads");
    const documentPath = path.resolve(uploadsDirectory, filename);

    if (path.dirname(documentPath) !== uploadsDirectory) {
        return res.status(400).send("Invalid document path.");
    }

    fs.access(documentPath, fs.constants.R_OK, (err) => {
        if (err) {
            return res.status(404).send("Document not found.");
        }

        res.sendFile(documentPath);
    });
});

app.get("/incident-media/:filename", requireOfficial, (req, res) => {
    const { filename } = req.params;

    if (!/^[a-zA-Z0-9._-]+$/.test(filename)) {
        return res.status(400).send("Invalid media filename.");
    }

    const uploadsDirectory = path.resolve(__dirname, "uploads");
    const mediaPath = path.resolve(uploadsDirectory, filename);

    if (path.dirname(mediaPath) !== uploadsDirectory) {
        return res.status(400).send("Invalid media path.");
    }

    fs.access(mediaPath, fs.constants.R_OK, (err) => {
        if (err) {
            return res.status(404).send("Incident media not found.");
        }

        res.sendFile(mediaPath);
    });
});

// Serve HTML files
app.use(express.static(path.join(__dirname, "public"), {
    index: "index.html"
}));

app.get("/resident-login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "resident-login.html"));
});

app.get("/official-login", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "official-login.html"));
});

// Get pending verification requests
app.get("/verification-requests", requireOfficial, (req, res) => {

    const sql = `
        SELECT *
        FROM resident_verification
        WHERE status = 'Pending'
        ORDER BY submitted_at DESC
    `;

    db.query(sql, (err, results) => {

        if (err) {
            console.log("Error getting verification requests:", err.message);
            return res.status(500).json({
                error: "Failed to get verification requests"
            });
        }

        res.json(results);
    });
});

app.post("/verification-requests/:verificationId/status", requireOfficial, (req, res) => {
    const verificationId = Number.parseInt(req.params.verificationId, 10);
    const { status } = req.body || {};

    if (!Number.isInteger(verificationId) || verificationId < 1) {
        return res.status(400).json({ error: "Invalid verification request ID" });
    }

    if (!['Approved', 'Rejected'].includes(status)) {
        return res.status(400).json({ error: "Invalid verification status" });
    }

    const sql = `
        UPDATE resident_verification
        SET status = ?
        WHERE verification_id = ? AND status = 'Pending'
    `;

    db.query(sql, [status, verificationId], (err, result) => {
        if (err) {
            console.log("Error updating verification status:", err.message);
            return res.status(500).json({ error: "Failed to update verification status" });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Pending verification request not found" });
        }

        res.json({ message: `Verification request ${status.toLowerCase()}.` });
    });
});

app.post("/submit-incident", requireResident, (req, res, next) => {
    incidentUpload.single("incident_media")(req, res, (uploadError) => {
        if (uploadError) {
            if (uploadError.code === "LIMIT_FILE_SIZE") {
                return res.status(400).send("The photo or video must not exceed 50 MB.");
            }

            return res.status(400).send(uploadError.message);
        }

        next();
    });
}, (req, res) => {
    const { description, location } = req.body || {};

    if (!description || !location || description.length > 5000 || location.length > 255) {
        return res.status(400).send("Please provide a valid incident description and location.");
    }

    const sql = `
        INSERT INTO incident_reports
        (resident_id, description, location, media_filename, media_type)
        VALUES (?, ?, ?, ?, ?)
    `;

    db.query(
        sql,
        [
            req.session.resident_id,
            description,
            location,
            req.file ? req.file.filename : null,
            req.file ? req.file.mimetype : null
        ],
        (err, result) => {
            if (err) {
                console.log("Error saving incident report:", err.message);
                return res.status(500).send("There was an error submitting your incident report.");
            }

            const ticketNumber = String(result.insertId).padStart(6, "0");

            recordIncidentTransaction(result.insertId, req.session.resident_id, null, "Pending", (transactionError) => {
                if (transactionError) {
                    console.log("Incident transaction logging error:", transactionError.message);
                    return res.status(500).send("Your report was saved, but its transaction record could not be saved. Please contact a barangay official before submitting it again.");
                }

                req.session.save((saveError) => {
                    if (saveError) {
                        console.log("Resident session save after incident error:", saveError.message);
                        return res.status(500).send("There was an error returning to your resident dashboard.");
                    }

                    res.redirect(`/resident.html?submitted=1&ticket=${ticketNumber}`);
                });
            });
        }
    );
});

app.get("/resident-incidents", requireResident, (req, res) => {
    db.query(
        `SELECT incident_id, description, location, media_filename, rejection_reason, status, submitted_at
         FROM incident_reports
         WHERE resident_id = ?
         ORDER BY submitted_at DESC`,
        [req.session.resident_id],
        (err, results) => {
            if (err) {
                console.log("Error getting resident incidents:", err.message);
                return res.status(500).json({ error: "Failed to get incident reports" });
            }

            res.json(results);
        }
    );
});

app.get("/resident-security-question", requireResident, (req, res) => {
    db.query(
        "SELECT security_question, security_answer_hash FROM resident_accounts WHERE resident_id = ?",
        [req.session.resident_id],
        (err, results) => {
            if (err) {
                console.log("Resident security setup lookup error:", err.message);
                return res.status(500).json({ error: "Unable to check recovery setup." });
            }

            if (results.length === 0) {
                return res.status(404).json({ error: "Resident account not found." });
            }

            res.json({
                configured: Boolean(results[0].security_question && results[0].security_answer_hash)
            });
        }
    );
});

app.post("/resident-security-question", requireResident, async (req, res) => {
    const securityQuestion = String(req.body?.security_question || "");
    const securityAnswer = String(req.body?.security_answer || "").trim().toLocaleLowerCase("en-US");

    if (!residentSecurityQuestions.includes(securityQuestion) || !securityAnswer || securityAnswer.length > 255) {
        return res.status(400).json({ error: "Choose a question and enter an answer up to 255 characters." });
    }

    try {
        const securityAnswerHash = await hashPassword(securityAnswer);
        db.query(
            `UPDATE resident_accounts
             SET security_question = ?, security_answer_hash = ?
             WHERE resident_id = ?
                 AND (security_question IS NULL OR security_answer_hash IS NULL)`,
            [securityQuestion, securityAnswerHash, req.session.resident_id],
            (err, result) => {
                if (err) {
                    console.log("Resident security setup save error:", err.message);
                    return res.status(500).json({ error: "Unable to save recovery setup." });
                }

                if (result.affectedRows === 0) {
                    return res.status(409).json({ error: "A recovery question is already set for this account." });
                }

                res.json({ message: "Recovery question saved." });
            }
        );
    } catch (hashError) {
        console.log("Resident security answer hashing error:", hashError.message);
        res.status(500).json({ error: "Unable to save recovery setup." });
    }
});

app.get("/incident-reports", requireOfficial, (req, res) => {
    db.query(
        `SELECT ir.incident_id, ir.description, ir.location, ir.media_filename, ir.media_type,
            ir.rejection_reason,
                ir.status, ir.submitted_at, ra.full_name
         FROM incident_reports ir
         JOIN resident_accounts ra ON ra.resident_id = ir.resident_id
         WHERE ir.status IN ('Pending', 'Processing')
         ORDER BY ir.submitted_at DESC`,
        (err, results) => {
            if (err) {
                console.log("Error getting incident reports:", err.message);
                return res.status(500).json({ error: "Failed to get incident reports" });
            }

            res.json(results);
        }
    );
});

app.get("/completed-resident-reports", requireOfficial, (req, res) => {
    const searchTerm = String(req.query.name || "").trim();
    if (searchTerm.length < 2) {
        return res.json([]);
    }

    if (/^\d{1,6}$/.test(searchTerm)) {
        const ticketNumber = searchTerm.padStart(6, "0");
        db.query(
            `SELECT ir.incident_id, ir.resident_id, ra.full_name, ir.description, ir.location,
                    ir.media_filename, ir.media_type, ir.rejection_reason, ir.status, ir.submitted_at
             FROM incident_reports ir
             JOIN resident_accounts ra ON ra.resident_id = ir.resident_id
             JOIN resident_verification rv ON rv.verification_id = ra.verification_id
             WHERE LPAD(CAST(ir.incident_id AS CHAR), 6, '0') = ?
                 AND rv.status = 'Approved'
             LIMIT 1`,
            [ticketNumber],
            (err, results) => {
                if (err) {
                    console.log("Ticket search error:", err.message);
                    return res.status(500).json({ error: "Failed to search report ticket" });
                }

                res.json({ type: "ticket", report: results[0] || null });
            }
        );
        return;
    }

    db.query(
        `SELECT ra.resident_id, ra.full_name, COUNT(ir.incident_id) AS report_count,
                MAX(ir.submitted_at) AS latest_report
         FROM resident_accounts ra
         JOIN resident_verification rv ON rv.verification_id = ra.verification_id
         LEFT JOIN incident_reports ir
             ON ir.resident_id = ra.resident_id
         WHERE rv.status = 'Approved'
             AND ra.full_name LIKE ?
         GROUP BY ra.resident_id, ra.full_name
         ORDER BY report_count DESC, latest_report DESC, ra.full_name ASC
         `,
        [`%${searchTerm}%`],
        (err, results) => {
            if (err) {
                console.log("Completed resident search error:", err.message);
                return res.status(500).json({ error: "Failed to search completed reports" });
            }

            res.json(results);
        }
    );
});

app.get("/resident-reports/:residentId", requireOfficial, (req, res) => {
    const residentId = Number.parseInt(req.params.residentId, 10);
    if (!Number.isInteger(residentId) || residentId < 1) {
        return res.status(400).json({ error: "Invalid resident ID" });
    }

    db.query(
        `SELECT incident_id, description, location, media_filename, media_type,
                rejection_reason, status, submitted_at
         FROM incident_reports
         WHERE resident_id = ?
         ORDER BY submitted_at DESC`,
        [residentId],
        (err, results) => {
            if (err) {
                console.log("Resident report history error:", err.message);
                return res.status(500).json({ error: "Failed to load resident report history" });
            }

            res.json(results);
        }
    );
});

app.post("/incident-reports/:incidentId/status", requireOfficial, (req, res) => {
    const incidentId = Number.parseInt(req.params.incidentId, 10);
    const status = String(req.body?.status || "");
    const rejectionReason = String(req.body?.rejection_reason || "").trim();

    if (!Number.isInteger(incidentId) || incidentId < 1 ||
        !["Pending", "Processing", "Resolved", "Rejected"].includes(status)) {
        return res.status(400).json({ error: "Invalid incident status update" });
    }

    if (status === "Rejected" && !rejectionReasons.includes(rejectionReason)) {
        return res.status(400).json({ error: "A rejection reason is required" });
    }

    db.query(
        "SELECT resident_id, status FROM incident_reports WHERE incident_id = ?",
        [incidentId],
        (lookupError, reports) => {
            if (lookupError) {
                console.log("Error finding incident report:", lookupError.message);
                return res.status(500).json({ error: "Failed to update incident status" });
            }

            if (reports.length === 0) {
                return res.status(404).json({ error: "Incident report not found" });
            }

            if (["Resolved", "Rejected"].includes(reports[0].status)) {
                return res.status(409).json({ error: "This incident already has a final status" });
            }

            const savedReason = status === "Rejected" ? rejectionReason : null;
            db.query(
                "UPDATE incident_reports SET status = ?, rejection_reason = ? WHERE incident_id = ?",
                [status, savedReason, incidentId],
                (err) => {
                    if (err) {
                        console.log("Error updating incident status:", err.message);
                        return res.status(500).json({ error: "Failed to update incident status" });
                    }

                    const logStatusChange = (onLogged) => {
                        recordIncidentTransaction(
                            incidentId,
                            reports[0].resident_id,
                            req.session.official_id,
                            status,
                            (transactionError) => {
                                if (transactionError) {
                                    console.log("Official incident transaction logging error:", transactionError.message);
                                    return res.status(500).json({
                                        error: "Incident status changed, but its transaction record could not be saved."
                                    });
                                }

                                onLogged();
                            }
                        );
                    };

                    if (status !== "Rejected") {
                        return logStatusChange(() => {
                            res.json({ message: "Incident status updated.", blocked: false });
                        });
                    }

                    logStatusChange(() => {
                        db.query(
                            `SELECT COUNT(*) AS false_information_count
                             FROM incident_reports
                             WHERE resident_id = ?
                                 AND status = 'Rejected'
                                 AND rejection_reason = 'False information'`,
                            [reports[0].resident_id],
                            (countError, countResults) => {
                                if (countError) {
                                    console.log("Error counting resident violations:", countError.message);
                                    return res.status(500).json({ error: "Incident was rejected, but account status could not be checked" });
                                }

                                const blocked = Number(countResults[0].false_information_count) >= 2;
                                if (!blocked) {
                                    return res.json({ message: "Incident rejected.", blocked: false });
                                }

                                db.query(
                                    "UPDATE resident_accounts SET is_blocked = TRUE WHERE resident_id = ?",
                                    [reports[0].resident_id],
                                    (blockError) => {
                                        if (blockError) {
                                            console.log("Error blocking resident account:", blockError.message);
                                            return res.status(500).json({ error: "Incident was rejected, but account could not be blocked" });
                                        }

                                        res.json({
                                            message: "Incident rejected. The resident has been blocked after two false-information violations.",
                                            blocked: true
                                        });
                                    }
                                );
                            }
                        );
                    });
                }
            );
        }
    );
});

app.post("/resident-register", upload.single("verification_document"), async (req, res) => {
    const {
        full_name,
        age,
        gender,
        address,
        purok,
        mobile_number,
        email,
        password,
        confirm_password,
        security_question,
        security_answer
    } = req.body || {};
    const parsedAge = Number.parseInt(age, 10);
    const cleanUploadedDocument = () => {
        if (req.file) {
            fs.unlink(req.file.path, () => {});
        }
    };

    if (password !== confirm_password) {
        cleanUploadedDocument();
        return res.redirect("/resident-register.html?status=password-mismatch");
    }

    if (!full_name || !Number.isInteger(parsedAge) || parsedAge < 1 ||
        !gender || !address || !purok || !mobile_number || !email ||
        !password || password.length < 8 || !req.file ||
        !residentSecurityQuestions.includes(security_question) || !String(security_answer || "").trim() ||
        String(security_answer).trim().length > 255) {
        cleanUploadedDocument();
        return res.status(400).send("Please complete all fields, choose a security question, provide its answer, upload an ID or certificate, and use a password of at least 8 characters.");
    }

    if (String(address).trim() !== requiredResidentAddress) {
        cleanUploadedDocument();
        return res.status(400).send(`Registration is only available to residents of ${requiredResidentAddress}.`);
    }

    db.query("SELECT resident_id FROM resident_accounts WHERE email = ?", [email], async (emailError, emailResults) => {
        if (emailError) {
            cleanUploadedDocument();
            console.log("Error checking resident email:", emailError.message);
            return res.status(500).send("There was an error checking your email.");
        }

        if (emailResults.length > 0) {
            cleanUploadedDocument();
            return res.redirect("/resident-register.html?status=email-taken");
        }

        const findVerificationSql = `
        SELECT rv.verification_id, rv.status,
               existing.resident_id AS existing_resident_id
        FROM resident_verification rv
        LEFT JOIN resident_accounts existing
            ON existing.full_name = rv.full_name
            AND existing.age = rv.age
            AND existing.gender = rv.gender
            AND existing.address = rv.address
            AND existing.purok = rv.purok
            AND existing.mobile_number = rv.mobile_number
        WHERE rv.full_name = ?
            AND rv.age = ?
            AND rv.gender = ?
            AND rv.address = ?
            AND rv.purok = ?
            AND rv.mobile_number = ?
        ORDER BY existing.resident_id IS NOT NULL DESC, rv.submitted_at DESC
        LIMIT 1
    `;

        db.query(
            findVerificationSql,
            [full_name, parsedAge, gender, address, purok, mobile_number],
            async (findError, results) => {
                if (findError) {
                    cleanUploadedDocument();
                    console.log("Error checking resident verification:", findError.message);
                    return res.status(500).send("There was an error checking your verification status.");
                }

                if (results[0]?.existing_resident_id) {
                    cleanUploadedDocument();
                    return res.redirect("/resident-register.html?status=registered");
                }

                try {
                    const passwordHash = await hashPassword(password);
                    const securityAnswerHash = await hashPassword(String(security_answer).trim().toLocaleLowerCase("en-US"));
                    const createAccount = (verificationId, isNewVerification) => {
                        const insertSql = `
                            INSERT INTO resident_accounts
                            (verification_id, full_name, age, gender, address, purok, mobile_number, email, password_hash, security_question, security_answer_hash)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        `;

                        db.query(
                            insertSql,
                            [verificationId, full_name, parsedAge, gender, address, purok, mobile_number, email, passwordHash, security_question, securityAnswerHash],
                            (insertError) => {
                                if (insertError) {
                                    const respondWithError = () => {
                                        cleanUploadedDocument();
                                        if (insertError.code === "ER_DUP_ENTRY") {
                                            return res.redirect("/resident-register.html?status=email-taken");
                                        }
                                        console.log("Error creating resident account:", insertError.message);
                                        res.status(500).send("There was an error creating your account.");
                                    };

                                    if (isNewVerification) {
                                        return db.query("DELETE FROM resident_verification WHERE verification_id = ?", [verificationId], respondWithError);
                                    }

                                    return respondWithError();
                                }

                                if (!isNewVerification) {
                                    cleanUploadedDocument();
                                }
                                res.redirect("/resident-register.html?status=submitted");
                            }
                        );
                    };

                    const existingVerification = results[0];
                    if (existingVerification && ["Pending", "Approved"].includes(existingVerification.status)) {
                        return createAccount(existingVerification.verification_id, false);
                    }

                    db.query(
                        `INSERT INTO resident_verification
                            (full_name, age, gender, address, purok, mobile_number, verification_document)
                         VALUES (?, ?, ?, ?, ?, ?, ?)`,
                        [full_name, parsedAge, gender, address, purok, mobile_number, req.file.filename],
                        (verificationError, verificationResult) => {
                            if (verificationError) {
                                cleanUploadedDocument();
                                console.log("Error saving verification:", verificationError.message);
                                return res.status(500).send("There was an error submitting your registration.");
                            }

                            createAccount(verificationResult.insertId, true);
                        }
                    );
                } catch (hashError) {
                    cleanUploadedDocument();
                    console.log("Error hashing resident password:", hashError.message);
                    res.status(500).send("There was an error creating your account.");
                }
            }
        );
    });
});

app.post("/resident-login", (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
        return res.status(400).send("Email and password are required.");
    }

    db.query(
        `SELECT ra.resident_id, ra.email, ra.password_hash, ra.is_blocked, rv.status AS verification_status
         FROM resident_accounts ra
         JOIN resident_verification rv ON rv.verification_id = ra.verification_id
         WHERE ra.email = ?`,
        [email],
        async (err, results) => {
            if (err) {
                console.log("Resident login error:", err.message);
                return res.status(500).send("There was an error during login.");
            }

            if (results.length === 0) {
                return res.redirect("/resident-login.html?error=invalid-credentials");
            }

            try {
                const passwordMatches = await verifyPassword(password, results[0].password_hash);
                if (!passwordMatches) {
                    return res.redirect("/resident-login.html?error=invalid-credentials");
                }

                if (results[0].is_blocked) {
                    return res.redirect("/resident-login.html?error=blocked");
                }

                if (results[0].verification_status === "Pending") {
                    return res.redirect("/resident-login.html?error=pending");
                }

                if (results[0].verification_status === "Rejected") {
                    return res.redirect("/resident-login.html?error=rejected");
                }

                req.session.resident_id = results[0].resident_id;
                req.session.resident_email = results[0].email;
                req.session.save((saveError) => {
                    if (saveError) {
                        console.log("Resident session save error:", saveError.message);
                        return res.status(500).send("There was an error starting your session.");
                    }

                    res.redirect("/resident.html");
                });
            } catch (verifyError) {
                console.log("Resident password verification error:", verifyError.message);
                res.redirect("/resident-login.html?error=invalid-credentials");
            }
        }
    );
});

app.post("/resident-forgot-password", (req, res) => {
    const email = String(req.body?.email || "").trim();
    const securityQuestion = String(req.body?.security_question || "");
    const securityAnswer = String(req.body?.security_answer || "").trim().toLocaleLowerCase("en-US");

    if (!email || !residentSecurityQuestions.includes(securityQuestion) || !securityAnswer || securityAnswer.length > 255) {
        return res.redirect("/resident-reset-password.html?error=1");
    }

    db.query(
        "SELECT resident_id, security_question, security_answer_hash FROM resident_accounts WHERE email = ?",
        [email],
        async (err, results) => {
            if (err) {
                console.log("Password reset lookup error:", err.message);
                return res.status(500).send("There was an error requesting a password reset.");
            }

            if (results.length === 0) {
                return res.redirect("/resident-reset-password.html?error=1");
            }

            try {
                const answerMatches = await verifyPassword(securityAnswer, results[0].security_answer_hash);
                if (securityQuestion !== results[0].security_question || !answerMatches) {
                    return res.redirect("/resident-reset-password.html?error=1");
                }
            } catch (verifyError) {
                console.log("Security answer verification error:", verifyError.message);
                return res.status(500).send("There was an error verifying your security answer.");
            }

            const token = crypto.randomBytes(32).toString("hex");
            const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
            const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

            db.query(
                "INSERT INTO resident_password_resets (resident_id, token_hash, expires_at) VALUES (?, ?, ?)",
                [results[0].resident_id, tokenHash, expiresAt],
                (insertError) => {
                    if (insertError) {
                        console.log("Password reset creation error:", insertError.message);
                        return res.status(500).send("There was an error creating a password reset.");
                    }

                    const resetLink = `/resident-reset-password.html?token=${token}`;
                    res.send(`
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <title>Password Reset Link - Barangay Direct</title>
                            <link rel="stylesheet" href="/style.css">
                        </head>
                        <body class="login-page">
                            <h1>Password Reset Link</h1>
                            <p>This development link expires in 15 minutes and can only be used once.</p>
                            <p><a href="${resetLink}">Reset your password</a></p>
                            <p><a href="/resident-login.html">Back to Resident Login</a></p>
                        </body>
                        </html>
                    `);
                }
            );
        }
    );
});

app.post("/resident-reset-password", async (req, res) => {
    const token = String(req.body?.token || "");
    const password = String(req.body?.password || "");

    if (!/^[a-f0-9]{64}$/i.test(token) || password.length < 8) {
        return res.status(400).send("A valid reset token and password of at least 8 characters are required.");
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    db.query(
        `SELECT reset_id, resident_id
         FROM resident_password_resets
         WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW()
         LIMIT 1`,
        [tokenHash],
        async (err, results) => {
            if (err) {
                console.log("Password reset validation error:", err.message);
                return res.status(500).send("There was an error validating the reset link.");
            }

            if (results.length === 0) {
                return res.status(400).send("This reset link is invalid or expired.");
            }

            try {
                const passwordHash = await hashPassword(password);
                db.query(
                    "UPDATE resident_accounts SET password_hash = ? WHERE resident_id = ?",
                    [passwordHash, results[0].resident_id],
                    (updateError) => {
                        if (updateError) {
                            console.log("Password update error:", updateError.message);
                            return res.status(500).send("There was an error updating your password.");
                        }

                        db.query(
                            "UPDATE resident_password_resets SET used_at = NOW() WHERE reset_id = ?",
                            [results[0].reset_id],
                            (consumeError) => {
                                if (consumeError) {
                                    console.log("Password reset consume error:", consumeError.message);
                                    return res.status(500).send("Password changed, but the reset link could not be closed.");
                                }

                                res.redirect("/resident-login.html?reset=1");
                            }
                        );
                    }
                );
            } catch (hashError) {
                console.log("Password reset hashing error:", hashError.message);
                res.status(500).send("There was an error updating your password.");
            }
        }
    );
});

app.post("/resident-logout", requireResident, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.log("Resident logout error:", err.message);
            return res.status(500).send("There was an error logging out.");
        }

        res.clearCookie("connect.sid");
        res.redirect("/resident-login.html");
    });
});

app.post("/official-logout", (req, res) => {
    if (!req.session.official_id) {
        return res.redirect("/official-login.html");
    }

    req.session.destroy((err) => {
        if (err) {
            console.log("Official logout error:", err.message);
            return res.status(500).send("There was an error logging out.");
        }

        res.clearCookie("connect.sid");
        res.redirect("/official-login.html");
    });
});

app.post("/official-login", (req, res) => {

    const { username, password } = req.body || {};
    console.log("Username received:", username);

    const sql = `
        SELECT *
        FROM officials
        WHERE username = ? AND password = ?
    `;

    db.query(sql, [username, password], (err, results) => {

        if (err) {
            console.log("Login error:", err.message);
            return res.send("There was an error during login.");
        }

        if (results.length === 0) {
            return res.redirect("/official-login.html?error=invalid-credentials");
        }

        req.session.official_id = results[0].official_id;
        req.session.official_username = results[0].username;

        res.redirect("/official.html");
    });
});
// Protect official dashboard
app.get("/official.html", (req, res) => {

    if (!req.session.official_id) {
        return res.redirect("/official-login.html");
    }

    res.sendFile(path.join(__dirname, "public", "official.html"));
});
app.listen(3000, () => {
    console.log("Barangay Direct server is running on port 3000");
});