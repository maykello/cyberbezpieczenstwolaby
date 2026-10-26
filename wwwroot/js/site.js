(function () {
    if (!window.sessionIdleTimeoutSeconds) return;

    const maxIdle = window.sessionIdleTimeoutSeconds;
    const displayEl = document.getElementById('sessionTimerDisplay');
    let remainingSeconds = maxIdle;
    let isPinging = false;
    let lastPing = 0;

    function renderTime() {
        if (!displayEl) return;
        const mins = Math.floor(Math.max(0, remainingSeconds) / 60).toString().padStart(2, '0');
        const secs = (Math.max(0, remainingSeconds) % 60).toString().padStart(2, '0');
        displayEl.textContent = mins + ':' + secs;
    }

    function pingServer() {
        const now = Date.now();
        if (now - lastPing < 2000 || isPinging) return;
        isPinging = true;
        lastPing = now;

        fetch('/api/keep-alive')
            .then(res => {
                if (res.ok) {
                    remainingSeconds = maxIdle;
                    renderTime();
                }
            })
            .catch(() => {})
            .finally(() => {
                isPinging = false;
            });
    }

    function syncStatus() {
        fetch('/api/session-status')
            .then(res => res.json())
            .then(data => {
                if (data && data.authenticated) {
                    remainingSeconds = data.remainingSeconds;
                    renderTime();
                } else if (data && !data.authenticated) {
                    window.location.href = '/Account/Login?timeout=1';
                }
            })
            .catch(() => {});
    }

    ['mousemove', 'mousedown', 'keydown', 'keypress', 'input', 'scroll', 'click', 'touchstart'].forEach(e => {
        window.addEventListener(e, pingServer, { passive: true });
    });

    renderTime();
    syncStatus();

    setInterval(function () {
        remainingSeconds--;
        renderTime();

        if (remainingSeconds <= 0) {
            window.location.href = '/Account/Login?timeout=1';
        }
    }, 1000);

    setInterval(syncStatus, 5000);
})();
