// client-auth.js - Add this file to your project
const maxLoginAttempts = 5;
let loginAttempts = 0;
let isLocked = false;
let lockoutTime = 300; // 5 minutes in seconds
let lockoutInterval;

// Keep track of redirect attempts to prevent loops
const REDIRECT_LIMIT = 3;
let redirectCount = parseInt(sessionStorage.getItem('redirectCount') || '0');

document.addEventListener("DOMContentLoaded", async () => {
  try {
    // Check if we're on an admin page
    const isAdminPage =
      window.location.pathname.includes("/AdHome") ||
      window.location.pathname.includes("/admincalender") ||
      window.location.pathname.includes("/analytics") ||
      window.location.pathname.includes("/hotable") ||
      window.location.pathname.includes("/MonthlyPayments");

    // If we're already on the unauthorized page, don't check
    if (window.location.pathname.includes("/unauthorized.html")) {
      return;
    }

    if (!isAdminPage) {
      // Not an admin page, reset redirect counter and return
      sessionStorage.removeItem('redirectCount');
      return;
    }

    // Increment and check redirect count to prevent loops
    redirectCount++;
    sessionStorage.setItem('redirectCount', redirectCount.toString());
    
    if (redirectCount > REDIRECT_LIMIT) {
      console.log("Redirect loop detected, redirecting to HoHome.html");
      sessionStorage.removeItem('redirectCount');
      window.location.href = "/HoHome.html";
      return;
    }

    console.log("Admin page detected, checking authentication...");

    // Check authentication status
    const response = await fetch("/api/auth-status", {
      method: "GET",
      credentials: "include",
      headers: {
        Accept: "application/json",
        "Cache-Control": "no-cache, no-store, must-revalidate",
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error: ${response.status}`);
    }

    const data = await response.json();
    console.log("Auth status response:", data);

    // If not authenticated or not admin, redirect to unauthorized page
    if (!data.authenticated || data.user.role !== "admin") {
      console.log("Not authenticated as admin, redirecting to unauthorized page");
      window.location.href = "/Webpages/unauthorized.html";
      return;
    }

    // If we get here, user is authenticated and is admin
    // Reset redirect counter as authentication was successful
    sessionStorage.removeItem('redirectCount');
    
  } catch (error) {
    console.error("Error checking authentication:", error);
    // On error, redirect to unauthorized page
    window.location.href = "/Webpages/unauthorized.html";
  }
});
