const axios = require('axios');
const fs = require('fs');
const path = require('path');

function checkStreamerStatus(streamerId, clientId) {
    return new Promise((resolve, reject) => {
        axios.get(`https://api.twitch.tv/helix/streams?user_id=${streamerId}`, {
            headers: {
                'Client-ID': clientId,
            }
        })
        .then(response => {
            const isLive = response.data.data.length > 0;
            resolve(isLive);
        })
        .catch(error => {
            console.error('Error fetching stream data:', error);
            reject(error);
        });
    });
}

function loadStreamers() {
    return new Promise((resolve, reject) => {
        fs.readFile(path.join(__dirname, 'streamers.json'), 'utf8', (err, data) => {
            if (err) {
                console.error('Error reading streamers.json:', err);
                reject(err);
            } else {
                const streamers = JSON.parse(data);
                resolve(streamers);
            }
        });
    });
}

async function checkAllStreamersStatus() {
    try {
        const clientId = 'jvpjgbm0dygvjqirgdnf6nzucsrdkr';
        const streamers = await loadStreamers();

        for (const streamer of streamers) {
            const isLive = await checkStreamerStatus(streamer.twitch_channel, clientId);
            streamer.is_live = isLive;
        }

        fs.writeFile(path.join(__dirname, 'streamers.json'), JSON.stringify(streamers, null, 2), 'utf8', (err) => {
            if (err) {
                console.error('Error writing to streamers.json:', err);
            } else {
                console.log('Streamer status updated successfully.');
            }
        });
    } catch (error) {
        console.error('Error checking streamer status:', error);
    }
}

setInterval(checkAllStreamersStatus, 60000);

checkAllStreamersStatus();

module.exports = {
    checkStreamerStatus,
    loadStreamers
};
