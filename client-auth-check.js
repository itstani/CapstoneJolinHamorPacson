// client-auth-check.js
document.addEventListener("DOMContentLoaded", async () => {
  // Check if we're on an admin page
  const isAdminPage =
    window.location.pathname.includes("/AdHome") ||
    window.location.pathname.includes("/admin/") ||
    window.location.pathname.includes("/hotable") ||
    window.location.pathname.includes("/admincalender") ||
    window.location.pathname.includes("/monthly-payments")

  if (!isAdminPage) {
    // Not an admin page, no need to check
    return
  }

  // Prevent redirect loops
  const redirectAttempts = Number.parseInt(sessionStorage.getItem("redirectAttempts") || "0")
  if (redirectAttempts > 3) {
    console.error("Too many redirect attempts, possible authentication loop")
    document.body.innerHTML = `
      <div style="text-align: center; margin-top: 100px;">
        <h2>Authentication Error</h2>
        <p>There was a problem with your authentication. Please try clearing your cookies and logging in again.</p>
        <button onclick="clearSessionAndRedirect()">Clear Session & Login Again</button>
      </div>
    `
    return
  }

  try {
    // Check authentication status
    const response = await fetch("/api/auth-status", {
      method: "GET",
      credentials: "include",
      headers: {
        Accept: "application/json",
        "Cache-Control": "no-cache",
      },
    })

    if (!response.ok) {
      throw new Error(`HTTP error: ${response.status}`)
    }

    const data = await response.json()

    // If not authenticated or not admin, redirect to login
    if (!data.authenticated || data.user.role !== "admin") {
      console.log("Not authenticated as admin, redirecting to login")
      sessionStorage.setItem("redirectAttempts", redirectAttempts + 1)
      window.location.href = "/login.html?unauthorized=true"
    } else {
      // Reset redirect attempts if authentication successful
      sessionStorage.removeItem("redirectAttempts")
    }
  } catch (error) {
    console.error("Error checking authentication:", error)
    // On error, redirect to login as a fallback
    window.location.href = "/login.html?error=true"
  }
})

function clearSessionAndRedirect() {
  // Clear session storage
  sessionStorage.clear()

  // Clear cookies
  document.cookie.split(";").forEach((c) => {
    document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/")
  })

  // Redirect to login
  window.location.href = "/login.html"
}
