// Add this script to each of your admin pages, right after the opening <body> tag
// This provides an additional layer of client-side protection

// This is a small script to add to the top of each admin HTML file
// client-auth-check.js
document.addEventListener("DOMContentLoaded", async () => {
  try {
    // Check if we're already in a redirect loop
    const loopCount = parseInt(sessionStorage.getItem('authRedirectCount') || '0');
    if (loopCount > 2) {
      console.error("Detected potential redirect loop, stopping auth check");
      sessionStorage.removeItem('authRedirectCount');
      return; // Stop the auth check to break the loop
    }
    
    // Check if user is authenticated and has admin role
    const response = await fetch("/api/check-auth", {
      method: "GET",
      credentials: "include",
      headers: {
        Accept: "application/json",
        "Cache-Control": "no-cache",
      },
    });

    const data = await response.json();
    console.log("Auth check response:", data);

    // If not authenticated or not admin, redirect to login
    if (!data.authenticated || data.user.role !== "admin") {
      sessionStorage.setItem('authRedirectCount', (loopCount + 1).toString());
      window.location.href = "/login.html?unauthorized=true";
    } else {
      // Reset counter on successful auth
      sessionStorage.removeItem('authRedirectCount');
    }
  } catch (error) {
    console.error("Auth check failed:", error);
    // On error, redirect to login as a safety measure
    window.location.href = "/login.html?error=true";
  }
});