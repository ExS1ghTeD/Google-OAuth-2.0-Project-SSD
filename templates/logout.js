// Enhanced logout function
function performLogout() {
    // 1. Clear all client-side storage
    localStorage.clear();
    sessionStorage.clear();
    
    // 2. Make an API call to ensure server-side logout
    fetch('/logout', {
        method: 'GET',
        headers: {
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        },
        credentials: 'include'  // Include cookies
    })
    .then(() => {
        // 3. Redirect after server confirms
        window.location.href = '/';
    })
    .catch(error => {
        // 4. Fallback: redirect anyway
        console.error('Logout API failed:', error);
        window.location.href = '/';
    });
    
    // Prevent any further actions
    return false;
}

// Update your logout confirmation to use this
confirmLogout.addEventListener('click', function(e) {
    e.preventDefault();
    performLogout();
});