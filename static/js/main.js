// BREACH::HARBOR Frontend JavaScript

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    console.log('BREACH::HARBOR initialized');
    
    // Initialize tooltips
    initializeTooltips();
    
    // Setup HTMX event handlers
    setupHTMXHandlers();
    
    // Setup form validation
    setupFormValidation();
    
    // Setup real-time updates
    setupRealTimeUpdates();
});

// Initialize Bootstrap tooltips
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Setup HTMX event handlers
function setupHTMXHandlers() {
    // Show loading state on HTMX requests
    document.addEventListener('htmx:beforeRequest', function(event) {
        const target = event.target;
        target.classList.add('loading');
    });
    
    // Hide loading state after request
    document.addEventListener('htmx:afterRequest', function(event) {
        const target = event.target;
        target.classList.remove('loading');
        
        // Handle errors
        if (event.detail.xhr.status >= 400) {
            showAlert('error', 'An error occurred. Please try again.');
        }
    });
    
    // Handle successful responses
    document.addEventListener('htmx:afterSettle', function(event) {
        // Re-initialize tooltips for new content
        initializeTooltips();
        
        // Add fade-in animation to new content
        const newContent = event.target;
        newContent.classList.add('fade-in');
    });
}

// Setup form validation
function setupFormValidation() {
    // Password confirmation validation
    const passwordConfirm = document.getElementById('confirm_password');
    const password = document.getElementById('password');
    
    if (passwordConfirm && password) {
        passwordConfirm.addEventListener('input', function() {
            if (this.value !== password.value) {
                this.setCustomValidity('Passwords do not match');
            } else {
                this.setCustomValidity('');
            }
        });
    }
    
    // Real-time form validation
    const forms = document.querySelectorAll('.needs-validation');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });
}

// Setup real-time updates
function setupRealTimeUpdates() {
    // Auto-refresh dashboard stats every 30 seconds
    if (window.location.pathname === '/dashboard') {
        setInterval(function() {
            htmx.trigger('#dashboard-stats', 'refresh');
        }, 30000);
    }
    
    // Auto-refresh incident list every 15 seconds
    if (window.location.pathname === '/incidents') {
        setInterval(function() {
            htmx.trigger('#incident-list', 'refresh');
        }, 15000);
    }
}

// Utility functions
function showAlert(type, message, duration = 5000) {
    const alertContainer = document.getElementById('alerts') || createAlertContainer();
    
    const alertId = 'alert-' + Date.now();
    const alertHTML = `
        <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
            <i class="fas fa-${getAlertIcon(type)} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    alertContainer.insertAdjacentHTML('beforeend', alertHTML);
    
    // Auto-remove alert after duration
    setTimeout(function() {
        const alert = document.getElementById(alertId);
        if (alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }
    }, duration);
}

function createAlertContainer() {
    const container = document.createElement('div');
    container.id = 'alerts';
    container.className = 'position-fixed top-0 end-0 p-3';
    container.style.zIndex = '1050';
    document.body.appendChild(container);
    return container;
}

function getAlertIcon(type) {
    const icons = {
        'success': 'check-circle',
        'danger': 'exclamation-triangle',
        'warning': 'exclamation-circle',
        'info': 'info-circle',
        'error': 'exclamation-triangle'
    };
    return icons[type] || 'info-circle';
}

function formatDateTime(dateString) {
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    }).format(date);
}

function formatRelativeTime(dateString) {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now - date;
    
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days} day${days > 1 ? 's' : ''} ago`;
    if (hours > 0) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    if (minutes > 0) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    return 'Just now';
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(function() {
        showAlert('success', 'Copied to clipboard');
    }).catch(function() {
        showAlert('error', 'Failed to copy to clipboard');
    });
}

function confirmAction(message, callback) {
    if (confirm(message)) {
        callback();
    }
}

// Search functionality
function setupSearch(inputId, targetSelector) {
    const searchInput = document.getElementById(inputId);
    if (!searchInput) return;
    
    searchInput.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        const targets = document.querySelectorAll(targetSelector);
        
        targets.forEach(function(target) {
            const text = target.textContent.toLowerCase();
            const shouldShow = text.includes(searchTerm);
            target.style.display = shouldShow ? '' : 'none';
        });
    });
}

// Chart utilities (for future use with Chart.js)
function createChart(canvasId, type, data, options = {}) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    return new Chart(ctx, {
        type: type,
        data: data,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            ...options
        }
    });
}

// Export functions for global use
window.BreachHarbor = {
    showAlert,
    formatDateTime,
    formatRelativeTime,
    copyToClipboard,
    confirmAction,
    setupSearch,
    createChart
};