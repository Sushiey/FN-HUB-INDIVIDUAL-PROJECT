function startCountdownTimer() {

    function updateCountdown() {
        const now = new Date();
        const targetDate = new Date(now);
        targetDate.setUTCHours(0, 0, 0, 0);
        targetDate.setDate(targetDate.getDate() + 1);

        const timeRemaining = targetDate - now;
        const hours = Math.floor((timeRemaining % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((timeRemaining % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((timeRemaining % (1000 * 60)) / 1000);

        document.getElementById('countdownTimer').innerHTML = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }

    setInterval(updateCountdown, 1000);
    updateCountdown();

}

document.addEventListener('DOMContentLoaded', function() {
    startCountdownTimer();
});
