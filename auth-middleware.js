// auth-middleware.js
function protectAdminRoutes(req, res, next) {
  // List of admin pages that should be protected
  const adminPages = [
    "/AdHome.html",
    "/admincalender.html",
    "/analytics.html",
    "/hotable.html",
    "/MonthlyPayments.html",
    "/Webpages/AdHome.html",
    "/Webpages/admincalender.html",
    "/Webpages/analytics.html",
    "/Webpages/hotable.html",
    "/Webpages/MonthlyPayments.html",
  ];

  // Check if the requested path is an admin page
  const isAdminPage = adminPages.some((page) => req.path === page || req.path.endsWith(page));

  // If it's an admin page, check if user is authenticated and is an admin
  if (isAdminPage) {
    console.log(`Admin page requested: ${req.path}`);
    console.log("Session:", req.session);
    console.log("User:", req.session?.user);

    // Check if user is logged in and has admin role
    if (!req.session || !req.session.user || req.session.user.role !== "admin") {
      console.log("Unauthorized access attempt to admin page");

      // Prevent redirect loops by checking the referer
      const referer = req.get('Referer') || '';
      if (referer.includes('login.html')) {
        console.log("Detected potential redirect loop, allowing request to proceed");
        return next();
      }

      // Redirect to login page with unauthorized parameter
      return res.redirect("/login.html?unauthorized=true");
    }
  }

  // If not an admin page or user is authorized, proceed
  next();
}