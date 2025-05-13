// client-auth.js - Add this file to your project
document.addEventListener("DOMContentLoaded", async () => {
  try {
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

    console.log("Admin page detected, checking authentication...")

    // Add a cache-busting parameter to prevent cached responses
    const timestamp = new Date().getTime()

    // Check authentication status
    const response = await fetch(`/api/auth-status?t=${timestamp}`, {
      method: "GET",
      credentials: "include",
      headers: {
        Accept: "application/json",
        "Cache-Control": "no-cache, no-store, must-revalidate",
      },
    })

    if (!response.ok) {
      throw new Error(`HTTP error: ${response.status}`)
    }

    const data = await response.json()
    console.log("Auth status response:", data)

    // If not authenticated or not admin, redirect to login
    if (!data.authenticated || data.user.role !== "admin") {
      console.log("Not authenticated as admin, redirecting to login")
      window.location.href = "/login.html?unauthorized=true"
    }
  } catch (error) {
    console.error("Error checking authentication:", error)

    // Check if we're in a potential redirect loop
    const loopCount = Number.parseInt(localStorage.getItem("authLoopCount") || "0")

    if (loopCount > 3) {
      // We're in a loop, redirect to a special page to break it
      console.log("Detected authentication loop, breaking out")
      localStorage.removeItem("authLoopCount")
      window.location.href = "/break-auth-loop"
      return
    }

    // Increment loop counter
    localStorage.setItem("authLoopCount", (loopCount + 1).toString())

    // On error, redirect to login as a fallback
    window.location.href = "/login.html?error=true"
  }
})
