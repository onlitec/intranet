/**
 * Intranet ES-SERVIDOR - JavaScript Interactions
 * Handles form validation, loading states, and UI enhancements
 */

// ========================================
// Utility Functions
// ========================================

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `alert alert-${type}`;
    toast.style.position = 'fixed';
    toast.style.top = '20px';
    toast.style.right = '20px';
    toast.style.zIndex = '1000';
    toast.style.minWidth = '300px';
    toast.style.animation = 'slideInRight 0.3s ease-out';

    const icon = type === 'success' ? '✓' :
        type === 'error' ? '✕' :
            type === 'warning' ? '⚠' : 'ℹ';

    toast.innerHTML = `
        <span class="alert-icon">${icon}</span>
        <span class="alert-message">${message}</span>
    `;

    document.body.appendChild(toast);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

/**
 * Show loading spinner
 */
function showLoading(button) {
    const text = button.querySelector('.btn-text');
    const loader = button.querySelector('.btn-loader');

    if (text && loader) {
        button.disabled = true;
        text.style.display = 'none';
        loader.style.display = 'inline-flex';
    }
}

/**
 * Hide loading spinner
 */
function hideLoading(button) {
    const text = button.querySelector('.btn-text');
    const loader = button.querySelector('.btn-loader');

    if (text && loader) {
        button.disabled = false;
        text.style.display = 'inline';
        loader.style.display = 'none';
    }
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(() => {
            showToast('Copiado para a área de transferência!', 'success');
        }).catch(err => {
            console.error('Erro ao copiar:', err);
            showToast('Erro ao copiar texto', 'error');
        });
    } else {
        // Fallback para navegadores antigos
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            showToast('Copiado para a área de transferência!', 'success');
        } catch (err) {
            console.error('Erro ao copiar:', err);
            showToast('Erro ao copiar texto', 'error');
        }
        document.body.removeChild(textarea);
    }
}

// ========================================
// Form Validation
// ========================================

/**
 * Validate login form
 */
function validateLoginForm() {
    const form = document.getElementById('loginForm');
    if (!form) return;

    form.addEventListener('submit', function (e) {
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        if (!username || !password) {
            e.preventDefault();
            showToast('Por favor, preencha todos os campos', 'warning');
            return false;
        }

        // Show loading state
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) {
            showLoading(submitBtn);
        }
    });
}

// ========================================
// Logout Confirmation
// ========================================

/**
 * Confirm logout action
 */
function confirmLogout() {
    const logoutForms = document.querySelectorAll('form[action*="logout"]');

    logoutForms.forEach(form => {
        form.addEventListener('submit', function (e) {
            const confirmed = confirm('Tem certeza que deseja sair?');
            if (!confirmed) {
                e.preventDefault();
            }
        });
    });
}

// ========================================
// Auto-dismiss Flash Messages
// ========================================

/**
 * Auto-dismiss flash messages after delay
 */
function autoDismissFlashMessages() {
    const alerts = document.querySelectorAll('.alert');

    alerts.forEach(alert => {
        // Skip error messages (keep them visible)
        if (alert.classList.contains('alert-error')) {
            return;
        }

        // Dismiss success/info messages after 5 seconds
        setTimeout(() => {
            alert.style.animation = 'fadeOut 0.3s ease-out';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
}

// ========================================
// Keyboard Shortcuts
// ========================================

/**
 * Handle keyboard shortcuts
 */
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function (e) {
        // Ctrl/Cmd + K: Focus search (if exists)
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.querySelector('input[type="search"]');
            if (searchInput) {
                searchInput.focus();
            }
        }

        // Escape: Close modals, clear focus
        if (e.key === 'Escape') {
            document.activeElement.blur();
        }
    });
}

// ========================================
// Sidebar Toggle (Mobile)
// ========================================

function setupSidebarToggle() {
    const sidebar = document.getElementById('app-sidebar');
    const toggleBtn = document.querySelector('.sidebar-toggle');
    const backdrop = document.getElementById('sidebar-backdrop');
    const collapseToggle = document.querySelector('.sidebar-collapse-toggle');

    if (!sidebar) return;

    // Persistência do colapso (desktop)
    const isCollapsed = localStorage.getItem('sidebar-collapsed') === 'true';
    if (isCollapsed && window.innerWidth > 1024) {
        sidebar.classList.add('collapsed');
    }

    if (collapseToggle) {
        collapseToggle.addEventListener('click', function () {
            sidebar.classList.toggle('collapsed');
            localStorage.setItem('sidebar-collapsed', sidebar.classList.contains('collapsed'));
        });
    }

    if (!toggleBtn || !backdrop) return;

    function openSidebar() {
        sidebar.classList.add('open');
        backdrop.hidden = false;
        toggleBtn.setAttribute('aria-expanded', 'true');
        document.body.classList.add('sidebar-open');
    }

    function closeSidebar() {
        sidebar.classList.remove('open');
        backdrop.hidden = true;
        toggleBtn.setAttribute('aria-expanded', 'false');
        document.body.classList.remove('sidebar-open');
    }

    function isOpen() {
        return sidebar.classList.contains('open');
    }

    toggleBtn.addEventListener('click', function () {
        if (isOpen()) closeSidebar();
        else openSidebar();
    });

    backdrop.addEventListener('click', closeSidebar);

    sidebar.addEventListener('click', function (e) {
        const link = e.target.closest('a');
        if (link && window.innerWidth <= 1024) {
            closeSidebar();
        }
    });

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            closeSidebar();
        }
    });

    window.addEventListener('resize', function () {
        if (window.innerWidth > 1024) {
            closeSidebar();
        }
    });
}

// ========================================
// BRUTALIST REVEAL ANIMATIONS - MANDATORY
// ========================================

/**
 * Setup scroll-triggered reveal animations
 */
function setupRevealAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('active');
            }
        });
    }, observerOptions);
    
    // Observe all reveal elements
    document.querySelectorAll('.reveal, .reveal-left, .reveal-right').forEach(el => {
        observer.observe(el);
    });
}

/**
 * Setup aggressive micro-interactions
 */
function setupMicroInteractions() {
    // Enhanced button interactions
    document.querySelectorAll('.btn').forEach(btn => {
        btn.addEventListener('mouseenter', function() {
            this.style.transform = 'translateY(-2px) scale(1.02)';
        });
        
        btn.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0) scale(1)';
        });
    });
    
    // Card hover effects with 3D transform
    document.querySelectorAll('.card-clickable').forEach(card => {
        card.addEventListener('mouseenter', function(e) {
            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            this.style.transform = `perspective(1000px) rotateX(${(y - rect.height/2) * -0.01}deg) rotateY(${(x - rect.width/2) * 0.01}deg) translateY(-8px)`;
        });
        
        card.addEventListener('mousemove', function(e) {
            const rect = this.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            this.style.transform = `perspective(1000px) rotateX(${(y - rect.height/2) * -0.01}deg) rotateY(${(x - rect.width/2) * 0.01}deg) translateY(-8px)`;
        });
        
        card.addEventListener('mouseleave', function() {
            this.style.transform = 'perspective(1000px) rotateX(0) rotateY(0) translateY(0)';
        });
    });
    
    // Handle data-url clicks for cards and rows
    document.querySelectorAll('.card-clickable[data-url]').forEach(card => {
        card.addEventListener('click', function() {
            window.location = this.dataset.url;
        });
    });
    
    document.querySelectorAll('.row-clickable[data-url]').forEach(row => {
        row.addEventListener('click', function() {
            window.location = this.dataset.url;
        });
    });
}

/**
 * Setup floating animations for specific elements
 */
function setupFloatingAnimations() {
    document.querySelectorAll('.floating').forEach(el => {
        el.style.animation = 'float 6s ease-in-out infinite';
    });
    
    document.querySelectorAll('.pulse').forEach(el => {
        el.style.animation = 'pulse 2s ease-in-out infinite';
    });
}

// Add slide-in animation keyframes dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
    
    @keyframes fadeOut {
        from {
            opacity: 1;
        }
        to {
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// ========================================
// Initialize on DOM Ready
// ========================================

document.addEventListener('DOMContentLoaded', function () {
    // Initialize all features
    validateLoginForm();
    confirmLogout();
    autoDismissFlashMessages();
    setupKeyboardShortcuts();
    setupSidebarToggle();
    
    // BRUTALIST ENHANCEMENTS - MANDATORY
    setupRevealAnimations();
    setupMicroInteractions();
    setupFloatingAnimations();

    // Log app initialization
    console.log('✓ Intranet ES-SERVIDOR BRUTALIST inicializado');
});

// ========================================
// Export functions for global use
// ========================================

window.IntranetApp = {
    showToast,
    showLoading,
    hideLoading,
    copyToClipboard
};
