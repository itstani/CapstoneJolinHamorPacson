// Add this script to each of your admin pages, right after the opening <body> tag
// This provides an additional layer of client-side protection

// This is a small script to add to the top of each admin HTML file
document.addEventListener("DOMContentLoaded", async () => {
  try {
    // Check if user is authenticated and has admin role
    const response = await fetch("/api/check-auth", {
      method: "GET",
      credentials: "include",
      headers: {
        Accept: "application/json",
        "Cache-Control": "no-cache",
      },
    })

    const data = await response.json()

    // If not authenticated or not admin, redirect to login
    if (!data.authenticated || data.user.role !== "admin") {
      window.location.href = "/login.html?unauthorized=true"
    }
  } catch (error) {
    console.error("Auth check failed:", error)
    // On error, redirect to login as a safety measure
    window.location.href = "/login.html?error=true"
  }
})
