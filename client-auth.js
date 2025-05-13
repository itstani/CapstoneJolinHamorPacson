// client-auth.js - Add this file to your project
document.addEventListener("DOMContentLoaded", async () => {
  // Check if we're on an admin page
  const isAdminPage =
    window.location.pathname.includes("/AdHome") ||
    window.location.pathname.includes("/admincalender") ||
    window.location.pathname.includes("/analytics") ||
    window.location.pathname.includes("/hotable") ||
    window.location.pathname.includes("/MonthlyPayments")

  if (!isAdminPage) {
    // Not an admin page, no need to check
    return
  }

  try {
    // Check authentication status
    const response = await fetch("/api/check-auth", {
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
      window.location.href = "/login.html?unauthorized=true"
    }
  } catch (error) {
    console.error("Error checking authentication:", error)
    // On error, redirect to login as a fallback
    window.location.href = "/login.html?error=true"
  }
})
