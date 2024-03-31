const express = require('express');
const router = express.Router();

router.get('/', async (req, res) => {
    try {
        const response = await axios.get(
            "https://public-api.tracker.gg/api/v1/{titleSlug}/standard/profile/{platformSlug}/{platformUserIdentifier}",
            {
                headers: {
                    "TRN-Api-Key": "7cb5c3d8-3e73-4442-b71d-498ea3e976b8"
                }
            }
        );
        const playerStats = response.data.data;
        res.render('stats', { playerStats });
    } catch (error) {
        console.error("Error fetching player stats:", error);
        res.status(500).send("Error fetching player stats");
    }
});

module.exports = router;
