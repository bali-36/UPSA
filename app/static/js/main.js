/**
 * UPSA Main JavaScript
 * =====================
 * Shared utilities and interactive behaviors.
 */

document.addEventListener('DOMContentLoaded', function() {
    // Auto-dismiss flash messages after 5 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) bsAlert.close();
        }, 5000);
    });

    // Notification badge polling (every 30 seconds)
    if (document.querySelector('.notification-badge')) {
        setInterval(updateNotificationCount, 30000);
    }

    // Initialize Theme toggler
    initThemeToggle();
});

/**
 * Initialize theme toggler events and update local state
 */
function initThemeToggle() {
    const toggleBtns = document.querySelectorAll('#theme-toggle-btn, #theme-toggle-btn-public');
    if (toggleBtns.length === 0) return;

    function updateToggleIcon(theme) {
        toggleBtns.forEach(btn => {
            const icon = btn.querySelector('i');
            if (icon) {
                if (theme === 'dark') {
                    icon.className = 'fa-solid fa-sun';
                    btn.title = 'Switch to Light Mode';
                } else {
                    icon.className = 'fa-solid fa-moon';
                    btn.title = 'Switch to Dark Mode';
                }
            }
        });
    }

    const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
    updateToggleIcon(currentTheme);

    toggleBtns.forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            const activeTheme = document.documentElement.getAttribute('data-theme') || 'light';
            const newTheme = activeTheme === 'dark' ? 'light' : 'dark';

            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateToggleIcon(newTheme);

            // Dispatch global event for other features (like Chart.js) to re-render grid lines
            window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme: newTheme } }));
        });
    });
}

/**
 * Update notification badge count via API
 */
async function updateNotificationCount() {
    try {
        const resp = await fetch('/api/notifications/unread-count');
        const data = await resp.json();
        const badge = document.querySelector('.notification-badge');
        if (badge) {
            badge.textContent = data.count;
            badge.style.display = data.count > 0 ? 'inline' : 'none';
        }
    } catch (e) {
        // Silently fail
    }
}

/**
 * Mark a notification as read
 */
async function markNotificationRead(notifId) {
    try {
        await fetch(`/api/notifications/${notifId}/read`, { method: 'PUT' });
        const el = document.querySelector(`[data-notif-id="${notifId}"]`);
        if (el) el.classList.add('opacity-50');
        updateNotificationCount();
    } catch (e) {
        // Silently fail
    }
}
